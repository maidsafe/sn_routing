// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "mock_base"))]
mod tests;

use super::{
    bootstrapping_peer::{BootstrappingPeer, BootstrappingPeerDetails},
    common::{Approved, Base},
    elder::{Elder, ElderDetails},
};
use crate::{
    chain::{
        Chain, EldersChange, EldersInfo, GenesisPfxInfo, NetworkParams, OnlinePayload,
        SectionKeyInfo, SendAckMessagePayload,
    },
    error::{Result, RoutingError},
    event::Event,
    id::{FullId, P2pNode, PublicId},
    location::DstLocation,
    messages::{
        AccumulatingMessage, BootstrapResponse, Message, MessageWithBytes, QueuedMessage, Variant,
        VerifyStatus,
    },
    network_service::NetworkService,
    outbox::EventBox,
    parsec::{DkgResultWrapper, ParsecMap},
    pause::PausedState,
    relocation::{RelocateDetails, SignedRelocateDetails},
    rng::{self, MainRng},
    routing_message_filter::RoutingMessageFilter,
    signature_accumulator::SignatureAccumulator,
    state_machine::{State, Transition},
    time::Duration,
    timer::Timer,
    utils::LogIdent,
    xor_space::{Prefix, XorName},
    ConnectionInfo,
};
use itertools::Itertools;
use std::{
    collections::{BTreeSet, VecDeque},
    fmt::{self, Display, Formatter},
    mem,
    net::SocketAddr,
};

// Send our knowledge in a similar speed as GOSSIP_TIMEOUT
const KNOWLEDGE_TIMEOUT: Duration = Duration::from_secs(2);

pub struct AdultDetails {
    pub network_service: NetworkService,
    pub event_backlog: Vec<Event>,
    pub full_id: FullId,
    pub gen_pfx_info: GenesisPfxInfo,
    pub msg_backlog: Vec<QueuedMessage>,
    pub sig_accumulator: SignatureAccumulator,
    pub msg_filter: RoutingMessageFilter,
    pub timer: Timer,
    pub network_cfg: NetworkParams,
    pub rng: MainRng,
}

pub struct Adult {
    chain: Chain,
    network_service: NetworkService,
    event_backlog: Vec<Event>,
    full_id: FullId,
    gen_pfx_info: GenesisPfxInfo,
    /// Messages addressed to us that we cannot handle until we are promoted.
    msg_backlog: Vec<QueuedMessage>,
    sig_accumulator: SignatureAccumulator,
    parsec_map: ParsecMap,
    knowledge_timer_token: u64,
    msg_filter: RoutingMessageFilter,
    timer: Timer,
    rng: MainRng,
}

impl Adult {
    pub fn new(
        mut details: AdultDetails,
        parsec_map: ParsecMap,
        _outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let public_id = *details.full_id.public_id();
        let knowledge_timer_token = details.timer.schedule(KNOWLEDGE_TIMEOUT);

        let parsec_map = parsec_map.with_init(
            &mut details.rng,
            details.full_id.clone(),
            &details.gen_pfx_info,
        );

        let chain = Chain::new(
            details.network_cfg,
            public_id,
            details.gen_pfx_info.clone(),
            None,
        );

        let node = Self {
            chain,
            network_service: details.network_service,
            event_backlog: details.event_backlog,
            full_id: details.full_id,
            gen_pfx_info: details.gen_pfx_info,
            msg_backlog: details.msg_backlog,
            sig_accumulator: details.sig_accumulator,
            parsec_map,
            msg_filter: details.msg_filter,
            timer: details.timer,
            knowledge_timer_token,
            rng: details.rng,
        };

        Ok(node)
    }

    pub fn closest_known_elders_to(&self, _name: &XorName) -> impl Iterator<Item = &P2pNode> {
        self.chain.our_elders()
    }

    pub fn rebootstrap(mut self) -> Result<State, RoutingError> {
        let network_cfg = self.chain.network_cfg();

        // Try to join the same section, but using new id, otherwise the section won't accept us
        // due to duplicate votes.
        let range_inclusive = self.our_prefix().range_inclusive();
        let full_id = FullId::within_range(&mut self.rng, &range_inclusive);

        Ok(State::BootstrappingPeer(BootstrappingPeer::new(
            BootstrappingPeerDetails {
                network_service: self.network_service,
                full_id,
                network_cfg,
                timer: self.timer,
                rng: self.rng,
            },
        )))
    }

    pub fn relocate(
        self,
        conn_infos: Vec<ConnectionInfo>,
        details: SignedRelocateDetails,
    ) -> Result<State, RoutingError> {
        Ok(State::BootstrappingPeer(BootstrappingPeer::relocate(
            BootstrappingPeerDetails {
                network_service: self.network_service,
                full_id: self.full_id,
                network_cfg: self.chain.network_cfg(),
                timer: self.timer,
                rng: self.rng,
            },
            conn_infos,
            details,
        )))
    }

    pub fn into_elder(
        self,
        old_pfx: Prefix<XorName>,
        outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        let details = ElderDetails {
            chain: self.chain,
            network_service: self.network_service,
            event_backlog: self.event_backlog,
            full_id: self.full_id,
            gen_pfx_info: self.gen_pfx_info,
            msg_queue: Default::default(),
            msg_backlog: self.msg_backlog,
            sig_accumulator: self.sig_accumulator,
            parsec_map: self.parsec_map,
            // we reset the message filter so that the node can correctly process some messages as
            // an Elder even if it has already seen them as an Adult
            msg_filter: RoutingMessageFilter::new(),
            timer: self.timer,
            rng: self.rng,
        };

        Elder::from_adult(details, old_pfx, outbox).map(State::Elder)
    }

    pub fn pause(self) -> PausedState {
        PausedState {
            chain: self.chain,
            full_id: self.full_id,
            gen_pfx_info: self.gen_pfx_info,
            msg_filter: self.msg_filter,
            msg_queue: VecDeque::new(),
            msg_backlog: self.msg_backlog,
            network_service: self.network_service,
            network_rx: None,
            sig_accumulator: self.sig_accumulator,
            parsec_map: self.parsec_map,
        }
    }

    pub fn resume(state: PausedState, timer: Timer) -> Self {
        let knowledge_timer_token = timer.schedule(KNOWLEDGE_TIMEOUT);

        Self {
            chain: state.chain,
            network_service: state.network_service,
            event_backlog: Vec::new(),
            full_id: state.full_id,
            gen_pfx_info: state.gen_pfx_info,
            msg_backlog: state.msg_backlog,
            sig_accumulator: state.sig_accumulator,
            parsec_map: state.parsec_map,
            knowledge_timer_token,
            msg_filter: state.msg_filter,
            timer,
            rng: rng::new(),
        }
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain.our_prefix()
    }

    fn handle_relocate(
        &mut self,
        signed_msg: SignedRelocateDetails,
    ) -> Result<Transition, RoutingError> {
        if signed_msg.relocate_details().pub_id != *self.id() {
            // This `Relocate` message is not for us - it's most likely a duplicate of a previous
            // message that we already handled.
            return Ok(Transition::Stay);
        }

        debug!(
            "{} - Received Relocate message to join the section at {}.",
            self,
            signed_msg.relocate_details().destination
        );

        if !self.check_signed_relocation_details(&signed_msg) {
            return Ok(Transition::Stay);
        }

        let conn_infos: Vec<_> = self
            .chain
            .our_elders()
            .map(|p2p_node| p2p_node.connection_info().clone())
            .collect();

        // Disconnect from everyone we know.
        for addr in self
            .chain
            .known_nodes()
            .map(|node| node.connection_info().peer_addr)
        {
            self.network_service.disconnect(addr);
        }

        Ok(Transition::Relocate {
            details: signed_msg,
            conn_infos,
        })
    }

    // Since we are an adult we should only give info about our section elders and they would
    // further guide the joining node.
    // However this lead to a loop if the Adult is the new Elder so we use the same code as
    // in Elder and return Join in some cases.
    fn handle_bootstrap_request(&mut self, p2p_node: P2pNode, destination: XorName) {
        // Use same code as from Elder::respond_to_bootstrap_request.
        // This is problematic since Elders do additional checks before doing this.
        // This was necessary to merge the initial work for promotion demotion.
        let response = if self.our_prefix().matches(&destination) {
            let our_info = self.chain.our_info().clone();
            debug!(
                "{} - Sending BootstrapResponse::Join to {:?} ({:?})",
                self, p2p_node, our_info
            );
            BootstrapResponse::Join(our_info)
        } else {
            let conn_infos: Vec<_> = self
                .closest_known_elders_to(&destination)
                .map(|p2p_node| p2p_node.connection_info().clone())
                .collect();
            debug!(
                "{} - Sending BootstrapResponse::Rebootstrap to {}",
                self, p2p_node
            );
            BootstrapResponse::Rebootstrap(conn_infos)
        };

        self.send_direct_message(
            p2p_node.connection_info(),
            Variant::BootstrapResponse(response),
        )
    }

    fn handle_genesis_update(
        &mut self,
        gen_pfx_info: GenesisPfxInfo,
    ) -> Result<Transition, RoutingError> {
        info!("{} - Received GenesisUpdate: {:?}", self, gen_pfx_info);

        // An Adult can receive the same message from multiple Elders - bail early if we are
        // already up to date
        if gen_pfx_info.parsec_version <= self.gen_pfx_info.parsec_version {
            return Ok(Transition::Stay);
        }
        self.gen_pfx_info = gen_pfx_info.clone();
        self.parsec_map.init(
            &mut self.rng,
            self.full_id.clone(),
            &self.gen_pfx_info,
            &LogIdent::new(self.full_id.public_id()),
        );
        self.chain = Chain::new(self.chain.network_cfg(), *self.id(), gen_pfx_info, None);

        // We were not promoted during the last section change, so we are not going to need these
        // messages anymore. This also prevents the messages from becoming stale (fail the trust
        // check) when they are eventually taken from the backlog and swarmed to other nodes.
        self.msg_backlog.clear();

        Ok(Transition::Stay)
    }

    /// Handles a signature of a `SignedMessage`, and if we have enough to verify the signed
    /// message, handles it.
    fn handle_message_signature(
        &mut self,
        msg: AccumulatingMessage,
        src: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        if !self.chain.is_peer_elder(&src) {
            debug!(
                "{} - Received message signature from not known elder (still use it) {}, {:?}",
                self, src, msg
            );
        }

        if let Some(msg) = self.sig_accumulator.add_proof(msg, &self.log_ident()) {
            self.try_handle_message(None, msg, outbox)
        } else {
            Ok(Transition::Stay)
        }
    }
}

#[cfg(feature = "mock_base")]
impl Adult {
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn process_timers(&mut self) {
        self.timer.process_timers()
    }

    pub fn has_unpolled_observations(&self) -> bool {
        self.parsec_map.has_unpolled_observations()
    }

    pub fn unpolled_observations_string(&self) -> String {
        self.parsec_map.unpolled_observations_string()
    }
}

impl Base for Adult {
    fn network_service(&self) -> &NetworkService {
        &self.network_service
    }

    fn network_service_mut(&mut self) -> &mut NetworkService {
        &mut self.network_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn in_dst_location(&self, dst: &DstLocation) -> bool {
        self.chain.in_dst_location(dst)
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn rng(&mut self) -> &mut MainRng {
        &mut self.rng
    }

    fn finish_handle_transition(&mut self, outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - State changed to Adult finished.", self);

        let mut transition = Transition::Stay;

        for QueuedMessage { sender, message } in
            mem::replace(&mut self.msg_backlog, Default::default())
        {
            if let Transition::Stay = &transition {
                let msg = match MessageWithBytes::new(message, &self.log_ident()) {
                    Ok(msg) => msg,
                    Err(err) => {
                        error!("{} - Failed to make message {:?}", self, err);
                        continue;
                    }
                };

                match self.handle_filtered_message(sender, msg, outbox) {
                    Ok(new_transition) => transition = new_transition,
                    Err(err) => debug!("{} - {:?}", self, err),
                }
            } else {
                self.msg_backlog.push(message.into_queued(sender));
            }
        }

        transition
    }

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        if self.knowledge_timer_token == token {
            // TODO: send this only when the knowledge changes, not periodically.
            self.send_member_knowledge();
            self.knowledge_timer_token = self.timer.schedule(KNOWLEDGE_TIMEOUT);
        }

        Transition::Stay
    }

    fn handle_peer_lost(&mut self, peer_addr: SocketAddr, _: &mut dyn EventBox) -> Transition {
        debug!("{} - Lost peer {}", self, peer_addr);
        Transition::Stay
    }

    fn handle_message(
        &mut self,
        sender: Option<ConnectionInfo>,
        msg: Message,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        trace!("{} - Handle message {:?}", self, msg);

        match msg.variant {
            Variant::GenesisUpdate(info) => {
                let _: &Prefix<_> = msg.src.as_section()?;
                self.handle_genesis_update(*info)
            }
            Variant::Relocate(_) => {
                let _: &Prefix<_> = msg.src.as_section()?;
                let signed_relocate = SignedRelocateDetails::new(msg)?;
                self.handle_relocate(signed_relocate)
            }
            Variant::MessageSignature(accumulating_msg) => {
                self.handle_message_signature(*accumulating_msg, *msg.src.as_node()?, outbox)
            }
            Variant::ParsecRequest(version, request) => self.handle_parsec_request(
                version,
                request,
                msg.src.to_sender_node(sender)?,
                outbox,
            ),
            Variant::ParsecResponse(version, response) => {
                self.handle_parsec_response(version, response, *msg.src.as_node()?, outbox)
            }
            Variant::BootstrapRequest(name) => {
                self.handle_bootstrap_request(msg.src.to_sender_node(sender)?, name);
                Ok(Transition::Stay)
            }
            _ => unreachable!(),
        }
    }

    fn unhandled_message(&mut self, sender: Option<ConnectionInfo>, msg: Message) {
        match msg.variant {
            Variant::BootstrapResponse(_) => {
                debug!("{} Unhandled message, discarding: {:?}", self, msg);
            }
            _ => {
                debug!("{} Unhandled message, adding to backlog: {:?}", self, msg);
                self.msg_backlog.push(msg.into_queued(sender));
            }
        }
    }

    fn filter_incoming_message(&mut self, message: &MessageWithBytes) -> bool {
        self.msg_filter.filter_incoming(message).is_new()
    }

    fn should_handle_message(&self, msg: &Message) -> bool {
        match msg.variant {
            Variant::GenesisUpdate(_)
            | Variant::Relocate(_)
            | Variant::MessageSignature(_)
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::BootstrapRequest(_) => true,

            Variant::NeighbourInfo(_)
            | Variant::UserMessage(_)
            | Variant::NodeApproval(_)
            | Variant::AckMessage { .. }
            | Variant::JoinRequest(_)
            | Variant::MemberKnowledge(_)
            | Variant::BootstrapResponse(_) => false,
        }
    }

    fn verify_message(&self, msg: &Message) -> Result<bool> {
        msg.verify(self.chain.get_their_key_infos())
            .and_then(VerifyStatus::require_full)
            .map_err(|error| {
                self.log_verify_failure(msg, &error, self.chain.get_their_key_infos());
                error
            })?;

        Ok(true)
    }

    fn relay_message(&mut self, msg: &MessageWithBytes) -> Result<()> {
        // Send message to our elders so they can route it properly.
        trace!(
            "{}: Forwarding message {:?} via elder targets {:?}",
            self,
            msg.full_crypto_hash(),
            self.chain.our_elders().format(", ")
        );

        let msg_filter = &mut self.msg_filter;
        let targets: Vec<_> = self
            .chain
            .our_elders()
            .filter(|p2p_node| {
                msg_filter
                    .filter_outgoing(msg, p2p_node.public_id())
                    .is_new()
            })
            .map(|node| node.connection_info().clone())
            .collect();

        let cheap_bytes_clone = msg.full_bytes().clone();
        self.send_message_to_targets(&targets, targets.len(), cheap_bytes_clone);

        // we've seen this message - don't handle it again if someone else sends it to us
        let _ = self.msg_filter.filter_incoming(msg);

        Ok(())
    }
}

impl Approved for Adult {
    fn send_event(&mut self, event: Event, _: &mut dyn EventBox) {
        self.event_backlog.push(event)
    }

    fn parsec_map(&self) -> &ParsecMap {
        &self.parsec_map
    }

    fn parsec_map_mut(&mut self) -> &mut ParsecMap {
        &mut self.parsec_map
    }

    fn chain(&self) -> &Chain {
        &self.chain
    }

    fn chain_mut(&mut self) -> &mut Chain {
        &mut self.chain
    }

    fn set_pfx_successfully_polled(&mut self, _: bool) {
        // Doesn't do anything
    }

    fn is_pfx_successfully_polled(&self) -> bool {
        false
    }

    fn handle_relocate_polled(&mut self, _details: RelocateDetails) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_promote_and_demote_elders(
        &mut self,
        _new_infos: Vec<EldersInfo>,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_member_added(
        &mut self,
        _payload: OnlinePayload,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_member_removed(
        &mut self,
        _pub_id: PublicId,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_member_relocated(
        &mut self,
        _details: RelocateDetails,
        _node_knowledge: u64,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_dkg_result_event(
        &mut self,
        _participants: &BTreeSet<PublicId>,
        _dkg_result: &DkgResultWrapper,
    ) -> Result<(), RoutingError> {
        // TODO
        Ok(())
    }

    fn handle_section_info_event(
        &mut self,
        old_pfx: Prefix<XorName>,
        _neighbour_change: EldersChange,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        if self.chain.is_self_elder() {
            Ok(Transition::IntoElder { old_pfx })
        } else {
            debug!("{} - Unhandled SectionInfo event", self);
            Ok(Transition::Stay)
        }
    }

    fn handle_neighbour_info_event(
        &mut self,
        _elders_info: EldersInfo,
        _neighbour_change: EldersChange,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_relocate_prepare_event(
        &mut self,
        _payload: RelocateDetails,
        _count_down: i32,
        _outbox: &mut dyn EventBox,
    ) {
    }

    fn handle_their_key_info_event(
        &mut self,
        _key_info: SectionKeyInfo,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_send_ack_message_event(
        &mut self,
        _ack_payload: SendAckMessagePayload,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_prune_event(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled ParsecPrune event", self);
        Ok(())
    }
}

impl Display for Adult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Adult({}({:b}))", self.name(), self.our_prefix())
    }
}
