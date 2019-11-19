// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{common::Base, joining_peer::JoiningPeerDetails};
use crate::{
    chain::{DevParams, NetworkParams},
    error::{InterfaceError, RoutingError},
    event::Event,
    id::{FullId, P2pNode},
    messages::{BootstrapResponse, DirectMessage, HopMessage, RoutingMessage},
    outbox::EventBox,
    peer_map::PeerMap,
    relocation::{RelocatePayload, SignedRelocateDetails},
    rng::MainRng,
    routing_table::{Authority, Prefix},
    state_machine::{State, Transition},
    states::JoiningPeer,
    timer::Timer,
    xor_name::XorName,
    ConnectionInfo, NetworkService,
};
use log::LogLevel;
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    time::Duration,
};

/// Time after which bootstrap is cancelled (and possibly retried).
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

pub struct BootstrappingPeerDetails {
    pub network_service: NetworkService,
    pub full_id: FullId,
    pub network_cfg: NetworkParams,
    pub timer: Timer,
    pub rng: MainRng,
    pub dev_params: DevParams,
}

// State of Client or Node while bootstrapping.
pub struct BootstrappingPeer {
    pending_requests: HashSet<SocketAddr>,
    timeout_tokens: HashMap<u64, SocketAddr>,
    network_service: NetworkService,
    full_id: FullId,
    timer: Timer,
    rng: MainRng,
    relocate_details: Option<SignedRelocateDetails>,
    network_cfg: NetworkParams,
    dev_params: DevParams,
}

impl BootstrappingPeer {
    pub fn new(mut details: BootstrappingPeerDetails) -> Self {
        details.network_service.service_mut().bootstrap();
        Self {
            network_service: details.network_service,
            full_id: details.full_id,
            timer: details.timer,
            pending_requests: Default::default(),
            timeout_tokens: Default::default(),
            rng: details.rng,
            relocate_details: None,
            network_cfg: details.network_cfg,
            dev_params: details.dev_params,
        }
    }

    /// Create `BootstrappingPeer` for a node that is being relocated into another sections.
    pub fn relocate(
        details: BootstrappingPeerDetails,
        conn_infos: Vec<ConnectionInfo>,
        relocate_details: SignedRelocateDetails,
    ) -> Self {
        let mut node = Self {
            network_service: details.network_service,
            full_id: details.full_id,
            timer: details.timer,
            pending_requests: Default::default(),
            timeout_tokens: Default::default(),
            rng: details.rng,
            relocate_details: Some(relocate_details),
            network_cfg: details.network_cfg,
            dev_params: details.dev_params,
        };

        for conn_info in conn_infos {
            node.send_bootstrap_request(conn_info)
        }

        node
    }

    pub fn into_joining(
        self,
        p2p_nodes: Vec<P2pNode>,
        relocate_payload: Option<RelocatePayload>,
        _outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        let details = JoiningPeerDetails {
            network_service: self.network_service,
            full_id: self.full_id,
            network_cfg: self.network_cfg,
            timer: self.timer,
            rng: self.rng,
            p2p_nodes,
            relocate_payload,
            dev_params: self.dev_params,
        };

        Ok(State::JoiningPeer(JoiningPeer::new(details)))
    }

    fn send_bootstrap_request(&mut self, dst: ConnectionInfo) {
        if !self.pending_requests.insert(dst.peer_addr) {
            return;
        }

        debug!("{} Sending BootstrapRequest to {}.", self, dst.peer_addr);

        let token = self.timer.schedule(BOOTSTRAP_TIMEOUT);
        let _ = self.timeout_tokens.insert(token, dst.peer_addr);

        // If we are relocating, request bootstrap to the section matching the name given to us
        // by our section. Otherwise request bootstrap to the section matching our current name.
        let destination = if let Some(details) = self.relocate_details.as_ref() {
            details.content().destination
        } else {
            *self.name()
        };

        self.send_direct_message(&dst, DirectMessage::BootstrapRequest(destination));
        self.peer_map_mut().connect(dst);
    }

    fn join_section(
        &mut self,
        prefix: Prefix<XorName>,
        p2p_nodes: Vec<P2pNode>,
    ) -> Result<Transition, RoutingError> {
        let old_full_id = self.full_id.clone();

        if !prefix.matches(self.name()) {
            let new_full_id = FullId::within_range(&mut self.rng, &prefix.range_inclusive());
            info!(
                "{} - Changing name to {}.",
                self,
                new_full_id.public_id().name()
            );
            self.full_id = new_full_id;
        }

        let relocate_payload = if let Some(details) = self.relocate_details.take() {
            Some(RelocatePayload::new(
                details,
                self.full_id.public_id(),
                &old_full_id,
            )?)
        } else {
            None
        };

        Ok(Transition::IntoJoining {
            p2p_nodes,
            relocate_payload,
        })
    }

    fn reconnect_to_new_section(&mut self, new_conn_infos: Vec<ConnectionInfo>) {
        let old_conn_infos: Vec<_> = self.peer_map_mut().remove_all().collect();
        for conn_info in old_conn_infos {
            self.disconnect_from(conn_info.peer_addr);
        }

        self.pending_requests.clear();
        self.timeout_tokens.clear();

        for conn_info in new_conn_infos {
            self.send_bootstrap_request(conn_info);
        }
    }

    fn request_failed(&mut self) {
        if self.pending_requests.is_empty() {
            self.network_service.service_mut().bootstrap();
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

    fn peer_map(&self) -> &PeerMap {
        &self.network_service().peer_map
    }

    fn peer_map_mut(&mut self) -> &mut PeerMap {
        &mut self.network_service_mut().peer_map
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn rng(&mut self) -> &mut MainRng {
        &mut self.rng
    }

    fn handle_send_message(
        &mut self,
        _: Authority<XorName>,
        _: Authority<XorName>,
        _: Vec<u8>,
    ) -> Result<(), InterfaceError> {
        warn!("{} - Cannot handle SendMessage - not bootstrapped.", self);
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        if let Some(peer_addr) = self.timeout_tokens.remove(&token) {
            debug!(
                "{} - Timeout when trying to bootstrap against {}.",
                self, peer_addr
            );

            if !self.pending_requests.remove(&peer_addr) {
                return Transition::Stay;
            }

            let _ = self.peer_map_mut().disconnect(peer_addr);
            self.disconnect_from(peer_addr);
            self.request_failed()
        }

        Transition::Stay
    }

    fn handle_bootstrapped_to(&mut self, conn_info: ConnectionInfo) -> Transition {
        self.send_bootstrap_request(conn_info);
        Transition::Stay
    }

    fn handle_bootstrap_failure(&mut self, outbox: &mut dyn EventBox) -> Transition {
        info!("{} Failed to bootstrap. Terminating.", self);
        outbox.send_event(Event::Terminated);
        Transition::Terminate
    }

    fn handle_connected_to(
        &mut self,
        _conn_info: ConnectionInfo,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        Transition::Stay
    }

    fn handle_connection_failure(
        &mut self,
        peer_addr: SocketAddr,
        _: &mut dyn EventBox,
    ) -> Transition {
        let _ = self.pending_requests.remove(&peer_addr);
        let _ = self.peer_map_mut().disconnect(peer_addr);
        self.request_failed();
        Transition::Stay
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        p2p_node: P2pNode,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        // Ignore messages from peers we didn't send `BootstrapRequest` to.
        if !self.pending_requests.contains(p2p_node.peer_addr()) {
            debug!(
                "{} - Ignoring direct message from unexpected peer: {}: {:?}",
                self, p2p_node, msg
            );
            let _ = self.peer_map_mut().disconnect(*p2p_node.peer_addr());
            self.disconnect_from(*p2p_node.peer_addr());
            return Ok(Transition::Stay);
        }

        match msg {
            DirectMessage::BootstrapResponse(BootstrapResponse::Join { prefix, p2p_nodes }) => {
                info!("{} - Joining a section {:?}: {:?}", self, prefix, p2p_nodes);
                self.join_section(prefix, p2p_nodes)
            }
            DirectMessage::BootstrapResponse(BootstrapResponse::Rebootstrap(new_conn_infos)) => {
                info!(
                    "{} - Bootstrapping redirected to another set of peers: {:?}",
                    self, new_conn_infos
                );
                self.reconnect_to_new_section(new_conn_infos);
                Ok(Transition::Stay)
            }
            _ => {
                debug!(
                    "{} - Unhandled direct message from {}: {:?}",
                    self,
                    p2p_node.public_id(),
                    msg
                );
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        trace!("{} - Unhandled hop message: {:?}", self, msg);
        Ok(Transition::Stay)
    }

    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        log_or_panic!(
            LogLevel::Error,
            "{} - Tried to send a routing message: {:?}",
            self,
            routing_msg
        );
        Ok(())
    }

    fn dev_params(&self) -> &DevParams {
        &self.dev_params
    }

    fn dev_params_mut(&mut self) -> &mut DevParams {
        &mut self.dev_params
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
        chain::NetworkParams,
        id::FullId,
        messages::Message,
        mock::Network,
        quic_p2p::{Builder, Peer},
        state_machine::StateMachine,
        states::common::from_network_bytes,
        NetworkConfig, NetworkEvent,
    };
    use crossbeam_channel as mpmc;
    use unwrap::unwrap;

    #[test]
    // Check that losing our proxy connection while in the `BootstrappingPeer` state doesn't stall
    // and instead triggers a re-bootstrap attempt..
    fn lose_proxy_connection() {
        let mut network_cfg = NetworkParams::default();

        if cfg!(feature = "mock_base") {
            network_cfg.elder_size = 7;
            network_cfg.safe_section_size = 30;
        };

        let network = Network::new(Default::default());
        let mut rng = network.new_rng();

        // Start a bare-bones network service.
        let (event_tx, event_rx) = mpmc::unbounded();
        let node_a_endpoint = network.gen_addr();
        let config = NetworkConfig::node().with_endpoint(node_a_endpoint);
        let node_a_network_service = unwrap!(Builder::new(event_tx).with_config(config).build());

        // Construct a `StateMachine` which will start in the `BootstrappingPeer` state and
        // bootstrap off the network service above.
        let node_b_endpoint = network.gen_addr();
        let config = NetworkConfig::node()
            .with_hard_coded_contact(node_a_endpoint)
            .with_endpoint(node_b_endpoint);
        let node_b_full_id = FullId::gen(&mut rng);

        let mut node_b_outbox = Vec::new();

        let (_node_b_action_tx, mut node_b_state_machine) = StateMachine::new(
            move |network_service, timer, _outbox2| {
                State::BootstrappingPeer(BootstrappingPeer::new(BootstrappingPeerDetails {
                    network_service,
                    full_id: node_b_full_id,
                    network_cfg,
                    timer,
                    rng,
                    dev_params: Default::default(),
                }))
            },
            config,
            &mut node_b_outbox,
        );

        // Check the network service received `ConnectedTo`.
        network.poll();
        match unwrap!(event_rx.try_recv()) {
            NetworkEvent::ConnectedTo {
                peer: Peer::Node { .. },
            } => (),
            ev => panic!(
                "Should have received `ConnectedTo` event, received `{:?}`.",
                ev
            ),
        }

        // The state machine should have received the `BootstrappedTo` event and this will have
        // caused it to send a `BootstrapRequest` message.
        network.poll();
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);

        // Check the network service received the `BootstrapRequest`
        network.poll();
        if let NetworkEvent::NewMessage { peer_addr, msg } = unwrap!(event_rx.try_recv()) {
            assert_eq!(peer_addr, node_b_endpoint);

            let ok = match unwrap!(from_network_bytes(msg)) {
                Message::Direct(msg) => match *msg.content() {
                    DirectMessage::BootstrapRequest(_) => true,
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
        drop(node_a_network_service);
        network.poll();

        // ...which triggers `ConnectionFailure` on the state machine which then attempts to
        // rebootstrap..
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);
        assert!(node_b_outbox.is_empty());
        network.poll();

        // ... but there is no one to bootstrap to, so the bootstrap fails which causes the state
        // machine to terminate.
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);
        assert_eq!(node_b_outbox.len(), 1);
        assert_eq!(node_b_outbox[0], Event::Terminated);
    }

    fn step_at_least_once(machine: &mut StateMachine, outbox: &mut dyn EventBox) {
        let mut sel = mpmc::Select::new();
        machine.register(&mut sel);

        // Blocking step for the first one.
        let op_index = sel.ready();
        unwrap!(machine.step(op_index, outbox));

        // Exhaust any remaining step
        while machine.try_step(outbox).is_ok() {}
    }
}
