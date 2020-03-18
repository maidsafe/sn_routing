// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    approved_peer::{ApprovedPeer, ElderDetails},
    common::{Base, Core, BOUNCE_RESEND_DELAY},
};
use crate::{
    chain::{Chain, EldersInfo, GenesisPfxInfo, NetworkParams, SectionKeyInfo},
    error::{Result, RoutingError},
    event::{Connected, Event},
    id::{FullId, P2pNode},
    location::{DstLocation, SrcLocation},
    log_utils,
    messages::{
        BootstrapResponse, JoinRequest, Message, MessageHash, MessageWithBytes, Variant,
        VerifyStatus,
    },
    network_service::NetworkService,
    outbox::EventBox,
    parsec::ParsecMap,
    relocation::{RelocatePayload, SignedRelocateDetails},
    rng::MainRng,
    state_machine::{State, Transition},
    timer::Timer,
    xor_space::{Prefix, XorName},
};
use bytes::Bytes;
use fxhash::FxHashSet;
use std::{collections::HashMap, net::SocketAddr, time::Duration};

/// Time after which bootstrap is cancelled (and possibly retried).
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

/// Time after which an attempt to joining a section is cancelled (and possibly retried).
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(600);

// State of a node after bootstrapping, while joining a section
pub struct JoiningPeer {
    core: Core,
    stage: Stage,
    network_cfg: NetworkParams,
}

impl JoiningPeer {
    pub fn new(mut core: Core, network_cfg: NetworkParams) -> Self {
        core.network_service.service_mut().bootstrap();

        Self {
            core,
            stage: Stage::new(None),
            network_cfg,
        }
    }

    /// Create `JoiningPeer` for a node that is being relocated into another sections.
    pub fn relocate(
        core: Core,
        network_cfg: NetworkParams,
        conn_infos: Vec<SocketAddr>,
        relocate_details: SignedRelocateDetails,
    ) -> Self {
        let mut node = Self {
            core,
            stage: Stage::new(Some(relocate_details)),
            network_cfg,
        };

        for conn_info in conn_infos {
            node.send_bootstrap_request(conn_info)
        }

        node
    }

    pub fn approve(
        mut self,
        gen_pfx_info: GenesisPfxInfo,
        outbox: &mut dyn EventBox,
    ) -> Result<State> {
        let stage = match self.stage {
            Stage::Bootstrapping(_) => unreachable!(),
            Stage::Joining(stage) => stage,
        };

        let public_id = *self.core.full_id.public_id();
        let parsec_map = ParsecMap::default().with_init(
            &mut self.core.rng,
            self.core.full_id.clone(),
            &gen_pfx_info,
        );
        let chain = Chain::new(self.network_cfg, public_id, gen_pfx_info.clone(), None);

        let details = ElderDetails {
            chain,
            network_service: self.core.network_service,
            event_backlog: Default::default(),
            full_id: self.core.full_id,
            gen_pfx_info,
            msg_queue: Default::default(),
            sig_accumulator: Default::default(),
            parsec_map,
            msg_filter: self.core.msg_filter,
            timer: self.core.timer,
            rng: self.core.rng,
        };

        let connect_type = match stage.join_type {
            JoinType::First { .. } => Connected::First,
            JoinType::Relocate(_) => Connected::Relocate,
        };

        Ok(State::ApprovedPeer(ApprovedPeer::from_joining_peer(
            details,
            connect_type,
            outbox,
        )))
    }

    fn handle_bootstrap_response(
        &mut self,
        sender: P2pNode,
        response: BootstrapResponse,
    ) -> Result<()> {
        let name = *self.name();

        match &mut self.stage {
            Stage::Bootstrapping(_) => match response {
                BootstrapResponse::Join(elders_info) => {
                    info!(
                        "Joining a section {:?} (given by {:?})",
                        elders_info, sender
                    );
                    self.join_section(elders_info)
                }
                BootstrapResponse::Rebootstrap(new_conn_infos) => {
                    info!(
                        "Bootstrapping redirected to another set of peers: {:?}",
                        new_conn_infos
                    );
                    self.reconnect_to_new_section(new_conn_infos);
                    Ok(())
                }
            },
            Stage::Joining(stage) => match response {
                BootstrapResponse::Join(new_elders_info) => {
                    if new_elders_info.version() > stage.elders_info.version() {
                        if new_elders_info.prefix().matches(&name) {
                            info!(
                                "Newer Join response for our prefix {:?} from {:?}",
                                new_elders_info, sender
                            );
                            stage.elders_info = new_elders_info;
                            self.send_join_requests();
                        } else {
                            log_or_panic!(
                                log::Level::Error,
                                "Newer Join response not for our prefix {:?} from {:?}",
                                new_elders_info,
                                sender,
                            );
                        }
                    }

                    Ok(())
                }
                BootstrapResponse::Rebootstrap(_) => unreachable!(),
            },
        }
    }

    fn handle_node_approval(&mut self, gen_pfx_info: GenesisPfxInfo) -> Transition {
        info!(
            "This node has been approved to join the network at {:?}!",
            gen_pfx_info.elders_info.prefix(),
        );
        Transition::Approve { gen_pfx_info }
    }

    fn handle_bounce(&mut self, sender: P2pNode, message: Bytes) {
        trace!(
            "Received Bounce of {:?} from {}. Resending",
            MessageHash::from_bytes(&message),
            sender
        );
        self.send_message_to_target_later(sender.peer_addr(), message, BOUNCE_RESEND_DELAY);
    }

    fn send_bootstrap_request(&mut self, dst: SocketAddr) {
        let stage = match &mut self.stage {
            Stage::Bootstrapping(stage) => stage,
            Stage::Joining(_) => unreachable!(),
        };

        if !stage.pending_requests.insert(dst) {
            return;
        }

        let token = self.core.timer.schedule(BOOTSTRAP_TIMEOUT);
        let _ = stage.timeout_tokens.insert(token, dst);

        let destination = match &stage.relocate_details {
            Some(details) => *details.destination(),
            None => *self.name(),
        };

        debug!("Sending BootstrapRequest to {}.", dst);
        self.send_direct_message(&dst, Variant::BootstrapRequest(destination));
    }

    fn reconnect_to_new_section(&mut self, new_conn_infos: Vec<SocketAddr>) {
        match &mut self.stage {
            Stage::Bootstrapping(stage) => {
                for addr in stage.pending_requests.drain() {
                    self.core.network_service.disconnect(addr);
                }

                stage.timeout_tokens.clear();

                for conn_info in new_conn_infos {
                    self.send_bootstrap_request(conn_info);
                }
            }
            Stage::Joining(_) => unreachable!(),
        }
    }

    fn send_join_requests(&mut self) {
        let stage = match &mut self.stage {
            Stage::Bootstrapping(_) => unreachable!(),
            Stage::Joining(stage) => stage,
        };

        let relocate_payload = match &stage.join_type {
            JoinType::First { .. } => None,
            JoinType::Relocate(payload) => Some(payload),
        };

        let elders_version = stage.elders_info.version();
        let messages: Vec<_> = stage
            .elders_info
            .member_nodes()
            .map(|dst| {
                let join_request = JoinRequest {
                    elders_version,
                    relocate_payload: relocate_payload.cloned(),
                };

                (dst.clone(), Variant::JoinRequest(Box::new(join_request)))
            })
            .collect();

        for (dst, variant) in messages {
            info!("Sending JoinRequest to {}", dst);
            self.send_direct_message(dst.peer_addr(), variant);
        }
    }

    fn join_section(&mut self, elders_info: EldersInfo) -> Result<()> {
        let stage = match &mut self.stage {
            Stage::Bootstrapping(stage) => stage,
            Stage::Joining(_) => unreachable!(),
        };

        let relocate_details = stage.relocate_details.take();
        let destination = match &relocate_details {
            Some(details) => *details.destination(),
            None => *self.name(),
        };
        let old_full_id = self.core.full_id.clone();

        // Use a name that will match the destination even after multiple splits
        let extra_split_count = 3;
        let name_prefix = Prefix::new(
            elders_info.prefix().bit_count() + extra_split_count,
            destination,
        );

        if !name_prefix.matches(self.name()) {
            let new_full_id =
                FullId::within_range(&mut self.core.rng, &name_prefix.range_inclusive());
            info!("Changing name to {}.", new_full_id.public_id().name());
            self.core.full_id = new_full_id;
        }

        let join_type = if let Some(details) = relocate_details {
            let relocate_payload =
                RelocatePayload::new(details, self.core.full_id.public_id(), &old_full_id)?;

            JoinType::Relocate(relocate_payload)
        } else {
            let timeout_token = self.core.timer.schedule(JOIN_TIMEOUT);
            JoinType::First { timeout_token }
        };

        self.stage = Stage::Joining(JoiningStage {
            elders_info,
            join_type,
        });

        self.send_join_requests();

        Ok(())
    }
    fn rebootstrap(&mut self) {
        // TODO: preserve relocation details
        self.stage = Stage::new(None);
        self.core.full_id = FullId::gen(&mut self.core.rng);
    }

    fn verify_message_full(
        &self,
        msg: &Message,
        key_info: Option<&SectionKeyInfo>,
    ) -> Result<bool> {
        msg.verify(as_iter(key_info))
            .and_then(VerifyStatus::require_full)
            .map_err(|error| {
                self.log_verify_failure(msg, &error, as_iter(key_info));
                error
            })?;

        Ok(true)
    }
}

impl Base for JoiningPeer {
    fn network_service(&self) -> &NetworkService {
        &self.core.network_service
    }

    fn network_service_mut(&mut self) -> &mut NetworkService {
        &mut self.core.network_service
    }

    fn full_id(&self) -> &FullId {
        &self.core.full_id
    }

    fn in_dst_location(&self, dst: &DstLocation) -> bool {
        match dst {
            DstLocation::Node(name) => name == self.name(),
            DstLocation::Section(_) | DstLocation::Prefix(_) => false,
            DstLocation::Direct => true,
        }
    }

    fn timer(&self) -> &Timer {
        &self.core.timer
    }

    fn rng(&mut self) -> &mut MainRng {
        &mut self.core.rng
    }

    fn set_log_ident(&self) -> log_utils::Guard {
        use std::fmt::Write;
        log_utils::set_ident(|buffer| {
            write!(buffer, "JoiningPeer({}", self.name())?;

            if let Stage::Joining(stage) = &self.stage {
                write!(buffer, "({:b})", stage.elders_info.prefix())?
            }

            write!(buffer, ") ")
        })
    }

    fn handle_send_message(
        &mut self,
        _: SrcLocation,
        _: DstLocation,
        _: Vec<u8>,
    ) -> Result<(), RoutingError> {
        warn!("Cannot handle SendMessage - not joined.");
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        match &mut self.stage {
            Stage::Bootstrapping(stage) => {
                if let Some(peer_addr) = stage.timeout_tokens.remove(&token) {
                    debug!("Timeout when trying to bootstrap against {}.", peer_addr);

                    if !stage.pending_requests.remove(&peer_addr) {
                        return Transition::Stay;
                    }

                    self.core.network_service.disconnect(peer_addr);

                    if stage.pending_requests.is_empty() {
                        // Rebootstrap
                        self.core.network_service.service_mut().bootstrap();
                    }
                }
            }
            Stage::Joining(stage) => {
                let join_token = match stage.join_type {
                    JoinType::First { timeout_token } => timeout_token,
                    JoinType::Relocate(_) => return Transition::Stay,
                };

                if join_token == token {
                    debug!("Timeout when trying to join a section.");

                    for addr in stage
                        .elders_info
                        .member_nodes()
                        .map(|node| *node.peer_addr())
                    {
                        self.core.network_service.disconnect(addr);
                    }

                    self.rebootstrap();
                }
            }
        }

        Transition::Stay
    }

    fn handle_bootstrapped_to(&mut self, conn_info: SocketAddr) -> Transition {
        self.send_bootstrap_request(conn_info);
        Transition::Stay
    }

    fn handle_bootstrap_failure(&mut self, outbox: &mut dyn EventBox) -> Transition {
        info!("Failed to bootstrap. Terminating.");
        outbox.send_event(Event::Terminated);
        Transition::Terminate
    }

    fn handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        // Ignore messages from peers we didn't send `BootstrapRequest` to.
        if let Stage::Bootstrapping(stage) = &self.stage {
            let sender = msg.src.to_sender_node(sender)?;

            if !stage.pending_requests.contains(sender.peer_addr()) {
                debug!(
                    "Ignoring message from unexpected peer: {}: {:?}",
                    sender, msg,
                );
                self.core.network_service.disconnect(*sender.peer_addr());
                return Ok(Transition::Stay);
            }
        }

        match msg.variant {
            Variant::BootstrapResponse(response) => {
                self.handle_bootstrap_response(msg.src.to_sender_node(sender)?, response)?;
                Ok(Transition::Stay)
            }
            Variant::NodeApproval(gen_info) => {
                // Ensure src and dst are what we expect.
                let _: &Prefix<_> = msg.src.as_section()?;
                let _: &XorName = msg.dst.as_node()?;

                Ok(self.handle_node_approval(*gen_info))
            }
            Variant::Bounce { message, .. } => {
                self.handle_bounce(msg.src.to_sender_node(sender)?, message);
                Ok(Transition::Stay)
            }
            _ => unreachable!(),
        }
    }

    fn unhandled_message(&mut self, sender: Option<SocketAddr>, msg: Message, msg_bytes: Bytes) {
        match msg.variant {
            Variant::BootstrapResponse(_)
            | Variant::MemberKnowledge { .. }
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..) => (),
            _ => {
                let sender = sender.expect("sender missing");

                debug!(
                    "Unhandled message - bouncing: {:?}, hash: {:?}",
                    msg,
                    MessageHash::from_bytes(&msg_bytes)
                );

                let variant = Variant::Bounce {
                    elders_version: None,
                    message: msg_bytes,
                };

                self.send_direct_message(&sender, variant)
            }
        }
    }

    fn should_handle_message(&self, msg: &Message) -> bool {
        match msg.variant {
            Variant::BootstrapResponse(BootstrapResponse::Join(_)) | Variant::Bounce { .. } => true,
            Variant::BootstrapResponse(_) => self.stage.is_bootstrapping(),
            Variant::NodeApproval(_) => self.stage.is_joining(),
            Variant::NeighbourInfo(_)
            | Variant::UserMessage(_)
            | Variant::AckMessage { .. }
            | Variant::GenesisUpdate(_)
            | Variant::Relocate(_)
            | Variant::MessageSignature(_)
            | Variant::BootstrapRequest(_)
            | Variant::JoinRequest(_)
            | Variant::MemberKnowledge { .. }
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::Ping => false,
        }
    }

    fn is_message_handled(&self, msg: &MessageWithBytes) -> bool {
        self.core.msg_filter.contains_incoming(msg)
    }

    fn set_message_handled(&mut self, msg: &MessageWithBytes) {
        self.core.msg_filter.insert_incoming(msg)
    }

    fn relay_message(&mut self, sender: Option<SocketAddr>, msg: &MessageWithBytes) -> Result<()> {
        let sender = sender.expect("sender missing");

        trace!("Message not for us, bouncing: {:?}", msg);

        let variant = Variant::Bounce {
            elders_version: None,
            message: msg.full_bytes().clone(),
        };

        self.send_direct_message(&sender, variant);

        Ok(())
    }

    fn verify_message(&self, msg: &Message) -> Result<bool> {
        let join_type = match &self.stage {
            Stage::Bootstrapping(_) => None,
            Stage::Joining(stage) => Some(&stage.join_type),
        };

        match (&msg.variant, join_type) {
            (Variant::NodeApproval(_), Some(JoinType::Relocate(payload))) => {
                let details = payload.relocate_details();
                let key_info = &details.destination_key_info;
                self.verify_message_full(msg, Some(key_info))
            }
            (Variant::NodeApproval(_), Some(JoinType::First { .. })) => {
                // We don't have any trusted keys to verify this message, but we still need to
                // handle it.
                Ok(true)
            }
            (Variant::BootstrapResponse(_), _) | (Variant::Bounce { .. }, _) => {
                self.verify_message_full(msg, None)
            }
            _ => unreachable!("unexpected message to verify: {:?}", msg),
        }
    }
}

// Stage of joining the network.
enum Stage {
    Bootstrapping(BootstrappingStage),
    Joining(JoiningStage),
}

impl Stage {
    fn new(relocate_details: Option<SignedRelocateDetails>) -> Self {
        Self::Bootstrapping(BootstrappingStage {
            pending_requests: Default::default(),
            timeout_tokens: Default::default(),
            relocate_details,
        })
    }

    fn is_bootstrapping(&self) -> bool {
        matches!(self, Self::Bootstrapping(_))
    }

    fn is_joining(&self) -> bool {
        matches!(self, Self::Joining(_))
    }
}

struct BootstrappingStage {
    // Using `FxHashSet` for deterministic iteration order.
    pending_requests: FxHashSet<SocketAddr>,
    timeout_tokens: HashMap<u64, SocketAddr>,
    relocate_details: Option<SignedRelocateDetails>,
}

struct JoiningStage {
    elders_info: EldersInfo,
    join_type: JoinType,
}

#[allow(clippy::large_enum_variant)]
enum JoinType {
    // Node joining the network for the first time.
    First { timeout_token: u64 },
    // Node being relocated.
    Relocate(RelocatePayload),
}

fn as_iter(
    key_info: Option<&SectionKeyInfo>,
) -> impl Iterator<Item = (&Prefix<XorName>, &SectionKeyInfo)> {
    key_info
        .into_iter()
        .map(|key_info| (key_info.prefix(), key_info))
}

#[cfg(all(test, feature = "mock_base"))]
mod tests {
    use super::*;
    use crate::{
        chain::NetworkParams,
        id::FullId,
        messages::Message,
        mock::Environment,
        quic_p2p::{Builder, EventSenders, Peer},
        state_machine::{State, StateMachine},
        unwrap, NetworkConfig, NetworkEvent,
    };
    use crossbeam_channel as mpmc;
    use fake_clock::FakeClock;

    #[test]
    // Check that losing our proxy connection while in the bootstrapping stage doesn't stall
    // and instead triggers a re-bootstrap attempt..
    fn lose_proxy_connection() {
        let mut network_cfg = NetworkParams::default();

        if cfg!(feature = "mock_base") {
            network_cfg.elder_size = 7;
            network_cfg.safe_section_size = 30;
        };

        let env = Environment::new(Default::default());
        let mut rng = env.new_rng();

        // Start a bare-bones network service.
        let (event_tx, (event_rx, _)) = {
            let (node_tx, node_rx) = mpmc::unbounded();
            let (client_tx, client_rx) = mpmc::unbounded();
            (EventSenders { node_tx, client_tx }, (node_rx, client_rx))
        };
        let node_a_endpoint = env.gen_addr();
        let config = NetworkConfig::node().with_endpoint(node_a_endpoint);
        let node_a_network_service = unwrap!(Builder::new(event_tx).with_config(config).build());

        // Construct a `StateMachine` which will start in the `BootstrappingPeer` state and
        // bootstrap off the network service above.
        let node_b_endpoint = env.gen_addr();
        let config = NetworkConfig::node()
            .with_hard_coded_contact(node_a_endpoint)
            .with_endpoint(node_b_endpoint);
        let node_b_full_id = FullId::gen(&mut rng);

        let mut node_b_outbox = Vec::new();
        let (node_b_client_tx, _) = mpmc::unbounded();

        let (_node_b_action_tx, mut node_b_state_machine) = StateMachine::new(
            move |network_service, timer, _outbox2| {
                State::JoiningPeer(JoiningPeer::new(
                    Core {
                        full_id: node_b_full_id,
                        network_service,
                        msg_filter: Default::default(),
                        timer,
                        rng,
                    },
                    network_cfg,
                ))
            },
            config,
            node_b_client_tx,
            &mut node_b_outbox,
        );

        // Check the network service received `ConnectedTo`.
        env.poll();
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
        env.poll();
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);

        // Check the network service received the `BootstrapRequest`
        env.poll();
        if let NetworkEvent::NewMessage { peer, msg } = unwrap!(event_rx.try_recv()) {
            assert_eq!(peer.peer_addr(), node_b_endpoint);

            let message = unwrap!(Message::from_bytes(&msg));
            match message.variant {
                Variant::BootstrapRequest(_) => (),
                _ => panic!("Should have received a `BootstrapRequest`."),
            };
        } else {
            panic!("Should have received `NewMessage` event.");
        }

        // Drop the network service and let some time pass...
        drop(node_a_network_service);
        FakeClock::advance_time(BOOTSTRAP_TIMEOUT.as_secs() * 1000 + 1);
        env.poll();

        // ...which causes the bootstrap request to timeout and the node then attempts to
        // rebootstrap..
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);
        assert!(node_b_outbox.is_empty());
        env.poll();

        // ... but there is no one to bootstrap to, so the bootstrap fails which causes the state
        // machine to terminate.
        step_at_least_once(&mut node_b_state_machine, &mut node_b_outbox);
        assert_eq!(node_b_outbox.len(), 1);
        assert_eq!(node_b_outbox[0], Event::Terminated);
    }

    fn step_at_least_once(machine: &mut StateMachine, outbox: &mut dyn EventBox) {
        let mut sel = mpmc::Select::new();
        machine.register(&mut sel);

        // Step for the first one.
        let op_index = unwrap!(sel.try_ready());
        unwrap!(machine.step(op_index, outbox));

        // Exhaust any remaining steps
        loop {
            let mut sel = mpmc::Select::new();
            machine.register(&mut sel);

            if let Ok(op_index) = sel.try_ready() {
                unwrap!(machine.step(op_index, outbox));
            } else {
                break;
            }
        }
    }
}
