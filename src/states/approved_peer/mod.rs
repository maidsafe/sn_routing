// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "mock"))]
mod tests;

use super::{
    common::{Base, BOUNCE_RESEND_DELAY},
    JoiningPeer,
};
#[cfg(feature = "mock_base")]
use crate::id::PublicId;
use crate::{
    chain::{Chain, EldersInfo, GenesisPfxInfo, NetworkParams, MIN_AGE_COUNTER},
    core::Core,
    error::{Result, RoutingError},
    event::{Connected, Event},
    id::P2pNode,
    location::{DstLocation, SrcLocation},
    log_utils,
    messages::{Message, MessageHash, MessageWithBytes, QueuedMessage, Variant},
    outbox::EventBox,
    parsec::{generate_first_dkg_result, ParsecMap},
    pause::PausedState,
    relocation::SignedRelocateDetails,
    rng,
    signature_accumulator::SignatureAccumulator,
    stage::Approved,
    state_machine::{State, Transition},
    timer::Timer,
    xor_space::{Prefix, XorName},
};
use bytes::Bytes;
use std::{collections::BTreeMap, iter, net::SocketAddr};

pub struct ApprovedPeer {
    core: Core,
    stage: Approved,
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
    ) -> Result<Self, RoutingError> {
        let public_id = *core.full_id.public_id();
        let connection_info = core.transport.our_connection_info()?;
        let p2p_node = P2pNode::new(public_id, connection_info);
        let mut ages = BTreeMap::new();
        let _ = ages.insert(public_id, MIN_AGE_COUNTER);
        let first_dkg_result = generate_first_dkg_result(&mut core.rng);
        let gen_pfx_info = GenesisPfxInfo {
            elders_info: create_first_elders_info(p2p_node)?,
            public_keys: first_dkg_result.public_key_set,
            state_serialized: Vec::new(),
            ages,
            parsec_version: 0,
        };

        let node = Self::new(
            core,
            network_cfg,
            Connected::First,
            gen_pfx_info,
            first_dkg_result.secret_key_share,
            outbox,
        );

        info!("{} Started a new network as a seed node.", node.name());
        outbox.send_event(Event::Promoted);

        Ok(node)
    }

    // Create regular node.
    pub fn new(
        mut core: Core,
        network_cfg: NetworkParams,
        connect_type: Connected,
        gen_pfx_info: GenesisPfxInfo,
        secret_key_share: Option<bls::SecretKeyShare>,
        outbox: &mut dyn EventBox,
    ) -> Self {
        let chain = Chain::new(
            network_cfg,
            *core.full_id.public_id(),
            gen_pfx_info.clone(),
            secret_key_share,
        );

        let parsec_map =
            ParsecMap::default().with_init(&mut core.rng, core.full_id.clone(), &gen_pfx_info);

        let node = Self::from_parts(core, chain, parsec_map, Default::default(), gen_pfx_info);

        debug!("{} State changed to ApprovedPeer.", node.name());
        outbox.send_event(Event::Connected(connect_type));

        node
    }

    pub fn relocate(
        self,
        conn_infos: Vec<SocketAddr>,
        details: SignedRelocateDetails,
    ) -> Result<State, RoutingError> {
        Ok(State::JoiningPeer(JoiningPeer::relocate(
            self.core,
            self.stage.chain.network_cfg(),
            conn_infos,
            details,
        )))
    }

    pub fn pause(self) -> PausedState {
        PausedState {
            chain: self.stage.chain,
            full_id: self.core.full_id,
            gen_pfx_info: self.stage.gen_pfx_info,
            msg_filter: self.core.msg_filter,
            msg_queue: self.core.msg_queue,
            transport: self.core.transport,
            network_rx: None,
            sig_accumulator: self.stage.sig_accumulator,
            parsec_map: self.stage.parsec_map,
        }
    }

    pub fn resume(state: PausedState, timer: Timer) -> Self {
        let core = Core {
            full_id: state.full_id,
            transport: state.transport,
            msg_filter: state.msg_filter,
            msg_queue: state.msg_queue,
            timer,
            rng: rng::new(),
        };

        Self::from_parts(
            core,
            state.chain,
            state.parsec_map,
            state.sig_accumulator,
            state.gen_pfx_info,
        )
    }

    fn from_parts(
        mut core: Core,
        chain: Chain,
        parsec_map: ParsecMap,
        sig_accumulator: SignatureAccumulator,
        gen_pfx_info: GenesisPfxInfo,
    ) -> Self {
        Self {
            stage: Approved::new(&mut core, sig_accumulator, parsec_map, chain, gen_pfx_info),
            core,
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Public API
    ////////////////////////////////////////////////////////////////////////////

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.stage.chain.our_prefix()
    }

    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.stage.chain.our_elders()
    }

    pub fn closest_known_elders_to(&self, name: &XorName) -> impl Iterator<Item = &P2pNode> {
        self.stage
            .chain
            .closest_section_info(*name)
            .1
            .member_nodes()
    }

    /// Vote for a user-defined event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        self.stage.vote_for_user_event(event)
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
        match msg.variant {
            Variant::UserMessage { .. } => (),
            _ => trace!("Got {:?}", msg),
        }

        match msg.variant {
            Variant::NeighbourInfo(elders_info) => {
                // Ensure the src and dst are what we expect.
                let _: &Prefix<_> = msg.src.as_section()?;
                let _: &Prefix<_> = msg.dst.as_prefix()?;

                self.stage
                    .handle_neighbour_info(elders_info, msg.src, msg.dst)?;
            }
            Variant::UserMessage(content) => {
                outbox.send_event(Event::MessageReceived {
                    content,
                    src: msg.src.location(),
                    dst: msg.dst,
                });
            }
            Variant::AckMessage {
                src_prefix,
                ack_version,
            } => {
                self.stage.handle_ack_message(
                    src_prefix,
                    ack_version,
                    *msg.src.as_section()?,
                    *msg.dst.as_section()?,
                )?;
            }
            Variant::GenesisUpdate(info) => {
                let _: &Prefix<_> = msg.src.as_section()?;
                self.stage.handle_genesis_update(&mut self.core, *info)?;
            }
            Variant::Relocate(_) => {
                let _: &Prefix<_> = msg.src.as_section()?;
                let signed_relocate = SignedRelocateDetails::new(msg)?;
                return self.stage.handle_relocate(&mut self.core, signed_relocate);
            }
            Variant::MessageSignature(accumulating_msg) => {
                self.stage.handle_message_signature(
                    &mut self.core,
                    *accumulating_msg,
                    *msg.src.as_node()?,
                )?;
            }
            Variant::BootstrapRequest(name) => self.stage.handle_bootstrap_request(
                &mut self.core,
                msg.src.to_sender_node(sender)?,
                name,
            ),
            Variant::JoinRequest(join_request) => self.stage.handle_join_request(
                &mut self.core,
                msg.src.to_sender_node(sender)?,
                *join_request,
            ),
            Variant::MemberKnowledge(payload) => self.stage.handle_member_knowledge(
                &mut self.core,
                msg.src.to_sender_node(sender)?,
                payload,
            ),
            Variant::ParsecRequest(version, request) => {
                self.stage.handle_parsec_request(
                    &mut self.core,
                    version,
                    request,
                    msg.src.to_sender_node(sender)?,
                    outbox,
                )?;
            }
            Variant::ParsecResponse(version, response) => {
                self.stage.handle_parsec_response(
                    &mut self.core,
                    version,
                    response,
                    *msg.src.as_node()?,
                    outbox,
                )?;
            }
            Variant::Bounce {
                elders_version,
                message,
            } => self.handle_bounce(msg.src.to_sender_node(sender)?, elders_version, message),
            _ => unreachable!(),
        }

        Ok(Transition::Stay)
    }

    fn handle_bounce(&mut self, sender: P2pNode, sender_version: Option<u64>, msg_bytes: Bytes) {
        if let Some((_, version)) = self.stage.chain.find_section_by_member(sender.public_id()) {
            if sender_version
                .map(|sender_version| sender_version < version)
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
        self.stage.chain.in_dst_location(dst)
    }

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        let mut conn_peers: Vec<_> = self.stage.chain.elders().map(P2pNode::name).collect();
        conn_peers.sort_unstable();
        conn_peers.dedup();
        self.stage.chain.closest_names(&name, count, &conn_peers)
    }

    fn set_log_ident(&self) -> log_utils::Guard {
        use std::fmt::Write;
        log_utils::set_ident(|buffer| {
            write!(
                buffer,
                "{}({}({:b})) ",
                if self.stage.chain.is_self_elder() {
                    "Elder"
                } else {
                    "Adult"
                },
                self.name(),
                self.our_prefix()
            )
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

        self.stage.send_routing_message(
            &mut self.core,
            src,
            dst,
            Variant::UserMessage(content),
            None,
        )
    }

    fn handle_timeout(&mut self, token: u64, _outbox: &mut dyn EventBox) -> Transition {
        self.stage.handle_timeout(&mut self.core, token);
        Transition::Stay
    }

    fn finish_handle_input(&mut self, outbox: &mut dyn EventBox) -> Transition {
        match self.handle_messages(outbox) {
            Transition::Stay => (),
            transition => return transition,
        }

        self.stage.finish_handle_input(&mut self.core, outbox);
        Transition::Stay
    }

    fn handle_bootstrapped_to(&mut self, addr: SocketAddr) -> Transition {
        // A mature node doesn't need a bootstrap connection
        self.core.transport.disconnect(addr);
        Transition::Stay
    }

    fn handle_connection_failure(
        &mut self,
        addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        self.stage.handle_connection_failure(&mut self.core, addr);
        Transition::Stay
    }

    fn handle_peer_lost(
        &mut self,
        peer_addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        self.stage.handle_peer_lost(peer_addr);
        Transition::Stay
    }

    fn handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        self.stage.update_our_knowledge(&msg);
        self.core.msg_queue.push_back(msg.into_queued(sender));
        Ok(Transition::Stay)
    }

    fn unhandled_message(&mut self, sender: Option<SocketAddr>, msg: Message, msg_bytes: Bytes) {
        self.stage
            .unhandled_message(&mut self.core, sender, msg, msg_bytes)
    }

    fn relay_message(
        &mut self,
        _sender: Option<SocketAddr>,
        message: &MessageWithBytes,
    ) -> Result<()> {
        self.stage.send_signed_message(&mut self.core, message)
    }

    fn should_handle_message(&self, msg: &Message) -> bool {
        self.stage.should_handle_message(msg)
    }

    fn verify_message(&self, msg: &Message) -> Result<bool, RoutingError> {
        self.stage.verify_message(msg)
    }
}

#[cfg(feature = "mock_base")]
impl ApprovedPeer {
    pub fn chain(&self) -> &Chain {
        &self.stage.chain
    }

    pub fn has_unpolled_observations(&self) -> bool {
        self.stage.parsec_map.has_unpolled_observations()
    }

    pub fn unpolled_observations_string(&self) -> String {
        self.stage.parsec_map.unpolled_observations_string()
    }

    pub fn is_peer_our_elder(&self, pub_id: &PublicId) -> bool {
        self.stage.chain.is_peer_our_elder(pub_id)
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
        self.stage.parsec_map.last_version()
    }

    pub fn in_src_location(&self, src: &SrcLocation) -> bool {
        self.stage.chain.in_src_location(src)
    }
}

// Create `EldersInfo` for the first node.
fn create_first_elders_info(p2p_node: P2pNode) -> Result<EldersInfo, RoutingError> {
    let name = *p2p_node.name();
    let node = (name, p2p_node);
    EldersInfo::new(iter::once(node).collect(), Prefix::default(), iter::empty()).map_err(|err| {
        error!(
            "FirstNode({:?}) - Failed to create first EldersInfo: {:?}",
            name, err
        );
        err
    })
}
