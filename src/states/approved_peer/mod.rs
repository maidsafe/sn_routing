// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "mock"))]
mod tests;

use super::common::Base;
#[cfg(feature = "mock_base")]
use crate::{chain::Chain, id::PublicId};
use crate::{
    chain::{EldersInfo, GenesisPfxInfo, NetworkParams},
    core::Core,
    error::{Result, RoutingError},
    event::{Connected, Event},
    id::{FullId, P2pNode},
    location::{DstLocation, SrcLocation},
    log_utils,
    messages::{BootstrapResponse, Message, MessageHash, MessageWithBytes, QueuedMessage, Variant},
    outbox::EventBox,
    pause::PausedState,
    relocation::{RelocatePayload, SignedRelocateDetails},
    stage::{Approved, Bootstrapping, BootstrappingStatus, Joining, RelocateParams, Stage},
    state_machine::Transition,
    time::Duration,
    timer::Timer,
    xor_space::{Prefix, XorName},
};
use bytes::Bytes;
use std::net::SocketAddr;

/// Delay after which a bounced message is resent.
pub const BOUNCE_RESEND_DELAY: Duration = Duration::from_secs(1);

pub struct ApprovedPeer {
    core: Core,
    stage: Stage,
}

impl ApprovedPeer {
    ////////////////////////////////////////////////////////////////////////////
    // Construction and transition
    ////////////////////////////////////////////////////////////////////////////

    // Create the first node in the network.
    pub fn first(
        mut core: Core,
        network_cfg: NetworkParams,
        outbox: &mut dyn EventBox,
    ) -> Result<Self> {
        let stage = Approved::first(&mut core, network_cfg)?;
        let node = Self {
            stage: Stage::Approved(stage),
            core,
        };

        info!("{} Started a new network as a seed node.", node.name());
        outbox.send_event(Event::Connected(Connected::First));
        outbox.send_event(Event::Promoted);

        Ok(node)
    }

    // Create regular node.
    pub fn new(mut core: Core, network_cfg: NetworkParams) -> Self {
        core.transport.bootstrap();

        Self {
            core,
            stage: Stage::Bootstrapping(Bootstrapping::new(network_cfg, None)),
        }
    }

    // TODO: return Result instead of panic
    pub fn pause(self) -> PausedState {
        let stage = match self.stage {
            Stage::Approved(stage) => stage,
            _ => unreachable!(),
        };

        stage.pause(self.core)
    }

    pub fn resume(state: PausedState, timer: Timer) -> Self {
        let (stage, core) = Approved::resume(state, timer);
        Self {
            stage: Stage::Approved(stage),
            core,
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Public API
    ////////////////////////////////////////////////////////////////////////////

    pub fn our_prefix(&self) -> Option<&Prefix<XorName>> {
        if let Stage::Approved(stage) = &self.stage {
            Some(stage.chain.our_prefix())
        } else {
            None
        }
    }

    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.stage
            .approved()
            .into_iter()
            .flat_map(|stage| stage.chain.our_elders())
    }

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

    /// Vote for a user-defined event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        if let Some(stage) = self.stage.approved_mut() {
            stage.vote_for_user_event(event)
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Message handling
    ////////////////////////////////////////////////////////////////////////////

    fn handle_messages(&mut self, outbox: &mut dyn EventBox) -> Transition {
        while let Some(QueuedMessage { message, sender }) = self.core.msg_queue.pop_front() {
            if self.in_dst_location(&message.dst) {
                match self.dispatch_message(sender, message, outbox) {
                    Ok(Transition::Stay) => (),
                    Ok(transition) => return transition,
                    Err(err) => debug!("Routing message dispatch failed: {:?}", err),
                }
            }
        }

        Transition::Stay
    }

    fn dispatch_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
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
                    self.approve(network_cfg, connect_type, *gen_pfx_info, outbox)
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
                        outbox,
                    )?;
                }
                Variant::ParsecResponse(version, response) => {
                    stage.handle_parsec_response(
                        &mut self.core,
                        version,
                        response,
                        *msg.src.as_node()?,
                        outbox,
                    )?;
                }
                Variant::UserMessage(content) => outbox.send_event(Event::MessageReceived {
                    content,
                    src: msg.src.location(),
                    dst: msg.dst,
                }),
                Variant::Bounce {
                    elders_version,
                    message,
                } => self.handle_bounce(msg.src.to_sender_node(sender)?, elders_version, message),
                Variant::NodeApproval(_) | Variant::BootstrapResponse(_) | Variant::Ping => {
                    unreachable!()
                }
            },
        }

        Ok(Transition::Stay)
    }

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
        outbox: &mut dyn EventBox,
    ) {
        info!(
            "This node has been approved to join the network at {:?}!",
            gen_pfx_info.elders_info.prefix(),
        );

        let stage = Approved::new(&mut self.core, network_cfg, gen_pfx_info, None);
        self.stage = Stage::Approved(stage);

        outbox.send_event(Event::Connected(connect_type));
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
}

impl Base for ApprovedPeer {
    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn in_dst_location(&self, dst: &DstLocation) -> bool {
        match &self.stage {
            Stage::Bootstrapping(_) | Stage::Joining(_) => match dst {
                DstLocation::Node(name) => name == self.core.name(),
                DstLocation::Section(_) | DstLocation::Prefix(_) => false,
                DstLocation::Direct => true,
            },
            Stage::Approved(stage) => stage.chain.in_dst_location(dst),
        }
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
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
        })
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
            Stage::Bootstrapping(_) | Stage::Joining(_) => {
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

    fn handle_timeout(&mut self, token: u64, _outbox: &mut dyn EventBox) -> Transition {
        match &mut self.stage {
            Stage::Bootstrapping(stage) => stage.handle_timeout(&mut self.core, token),
            Stage::Joining(stage) => {
                if stage.handle_timeout(&mut self.core, token) {
                    let network_cfg = stage.network_cfg;
                    self.rebootstrap(network_cfg)
                }
            }
            Stage::Approved(stage) => stage.handle_timeout(&mut self.core, token),
        }

        Transition::Stay
    }

    fn finish_handle_input(&mut self, outbox: &mut dyn EventBox) -> Transition {
        match self.handle_messages(outbox) {
            Transition::Stay => (),
            transition => return transition,
        }

        if let Stage::Approved(stage) = &mut self.stage {
            stage.finish_handle_input(&mut self.core, outbox);
        }

        Transition::Stay
    }

    fn handle_bootstrapped_to(&mut self, addr: SocketAddr) -> Transition {
        match &mut self.stage {
            Stage::Bootstrapping(stage) => stage.send_bootstrap_request(&mut self.core, addr),
            Stage::Joining(_) | Stage::Approved(_) => {
                // A bootstrapped node doesn't need another bootstrap connection
                self.core.transport.disconnect(addr);
            }
        }

        Transition::Stay
    }

    fn handle_bootstrap_failure(&mut self, outbox: &mut dyn EventBox) -> Transition {
        assert!(matches!(self.stage, Stage::Bootstrapping(_)));

        info!("Failed to bootstrap. Terminating.");
        outbox.send_event(Event::Terminated);
        Transition::Terminate
    }

    fn handle_connection_failure(
        &mut self,
        addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        if let Stage::Approved(stage) = &mut self.stage {
            stage.handle_connection_failure(&mut self.core, addr);
        } else {
            trace!("ConnectionFailure from {}", addr);
        }

        Transition::Stay
    }

    fn handle_peer_lost(
        &mut self,
        peer_addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        if let Stage::Approved(stage) = &mut self.stage {
            stage.handle_peer_lost(peer_addr);
        }

        Transition::Stay
    }

    fn handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        if let Stage::Approved(stage) = &mut self.stage {
            stage.update_our_knowledge(&msg);
        }

        self.core.msg_queue.push_back(msg.into_queued(sender));

        Ok(Transition::Stay)
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
        }
    }

    fn should_handle_message(&self, msg: &Message) -> bool {
        match &self.stage {
            Stage::Bootstrapping(stage) => stage.should_handle_message(msg),
            Stage::Joining(stage) => stage.should_handle_message(msg),
            Stage::Approved(stage) => stage.should_handle_message(msg),
        }
    }

    fn verify_message(&self, msg: &Message) -> Result<bool> {
        match &self.stage {
            Stage::Bootstrapping(stage) => stage.verify_message(msg),
            Stage::Joining(stage) => stage.verify_message(msg),
            Stage::Approved(stage) => stage.verify_message(msg),
        }
    }
}

#[cfg(feature = "mock_base")]
impl ApprovedPeer {
    pub fn chain(&self) -> Option<&Chain> {
        self.stage.approved().map(|stage| &stage.chain)
    }

    pub fn has_unpolled_observations(&self) -> bool {
        self.stage
            .approved()
            .map(|stage| stage.parsec_map.has_unpolled_observations())
            .unwrap_or(false)
    }

    pub fn unpolled_observations_string(&self) -> String {
        self.stage
            .approved()
            .map(|stage| stage.parsec_map.unpolled_observations_string())
            .unwrap_or_else(String::new)
    }

    pub fn is_peer_our_elder(&self, pub_id: &PublicId) -> bool {
        self.stage
            .approved()
            .map(|stage| stage.chain.is_peer_our_elder(pub_id))
            .unwrap_or(false)
    }

    pub fn send_msg_to_targets(
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

    pub fn parsec_last_version(&self) -> u64 {
        self.stage
            .approved()
            .map(|stage| stage.parsec_map.last_version())
            .unwrap_or(0)
    }

    pub fn in_src_location(&self, src: &SrcLocation) -> bool {
        self.stage
            .approved()
            .map(|stage| stage.chain.in_src_location(src))
            .unwrap_or(false)
    }
}
