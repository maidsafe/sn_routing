// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

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
    error::RoutingError,
    event::Event,
    id::{FullId, P2pNode, PublicId},
    messages::{
        BootstrapResponse, DirectMessage, HopMessage, RoutingMessage, SignedRoutingMessage,
    },
    outbox::EventBox,
    parsec::{DkgResultWrapper, ParsecMap},
    pause::PausedState,
    peer_map::PeerMap,
    relocation::{RelocateDetails, SignedRelocateDetails},
    rng::{self, MainRng},
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix},
    signature_accumulator::SignatureAccumulator,
    state_machine::{State, Transition},
    time::Duration,
    timer::Timer,
    utils::LogIdent,
    xor_name::XorName,
    BlsSignature, ConnectionInfo, NetworkService,
};
use itertools::Itertools;
use std::{
    collections::{BTreeSet, VecDeque},
    fmt::{self, Display, Formatter},
    mem,
    net::SocketAddr,
};

const POKE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct AdultDetails {
    pub network_service: NetworkService,
    pub event_backlog: Vec<Event>,
    pub full_id: FullId,
    pub gen_pfx_info: GenesisPfxInfo,
    pub routing_msg_backlog: Vec<SignedRoutingMessage>,
    pub direct_msg_backlog: Vec<(P2pNode, DirectMessage)>,
    pub sig_accumulator: SignatureAccumulator,
    pub routing_msg_filter: RoutingMessageFilter,
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
    /// Routing messages addressed to us that we cannot handle until we are established.
    routing_msg_backlog: Vec<SignedRoutingMessage>,
    direct_msg_backlog: Vec<(P2pNode, DirectMessage)>,
    sig_accumulator: SignatureAccumulator,
    parsec_map: ParsecMap,
    parsec_timer_token: u64,
    routing_msg_filter: RoutingMessageFilter,
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
        let parsec_timer_token = details.timer.schedule(POKE_TIMEOUT);

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
            routing_msg_backlog: details.routing_msg_backlog,
            direct_msg_backlog: details.direct_msg_backlog,
            sig_accumulator: details.sig_accumulator,
            parsec_map,
            routing_msg_filter: details.routing_msg_filter,
            timer: details.timer,
            parsec_timer_token,
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
            routing_msg_queue: Default::default(),
            routing_msg_backlog: self.routing_msg_backlog,
            direct_msg_backlog: self.direct_msg_backlog,
            sig_accumulator: self.sig_accumulator,
            parsec_map: self.parsec_map,
            // we reset the message filter so that the node can correctly process some messages as
            // an Elder even if it has already seen them as an Adult
            routing_msg_filter: RoutingMessageFilter::new(),
            timer: self.timer,
            rng: self.rng,
        };

        Elder::from_adult(details, old_pfx, outbox).map(State::Elder)
    }

    pub fn pause(self) -> Result<PausedState, RoutingError> {
        Ok(PausedState {
            chain: self.chain,
            full_id: self.full_id,
            gen_pfx_info: self.gen_pfx_info,
            routing_msg_filter: self.routing_msg_filter,
            routing_msg_queue: VecDeque::new(),
            routing_msg_backlog: self.routing_msg_backlog,
            direct_msg_backlog: self.direct_msg_backlog,
            network_service: self.network_service,
            network_rx: None,
            sig_accumulator: self.sig_accumulator,
            parsec_map: self.parsec_map,
        })
    }

    pub fn resume(state: PausedState, timer: Timer) -> Self {
        let parsec_timer_token = timer.schedule(POKE_TIMEOUT);

        Self {
            chain: state.chain,
            network_service: state.network_service,
            event_backlog: Vec::new(),
            full_id: state.full_id,
            gen_pfx_info: state.gen_pfx_info,
            routing_msg_backlog: state.routing_msg_backlog,
            direct_msg_backlog: state.direct_msg_backlog,
            sig_accumulator: state.sig_accumulator,
            parsec_map: state.parsec_map,
            parsec_timer_token,
            routing_msg_filter: state.routing_msg_filter,
            timer,
            rng: rng::new(),
        }
    }

    pub fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain.our_prefix()
    }

    fn dispatch_routing_message(
        &mut self,
        msg: SignedRoutingMessage,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        self.add_message_to_backlog(msg);
        Ok(())
    }

    // Sends a `ParsecPoke` message to trigger a gossip request from current section members to us.
    //
    // TODO: Should restrict targets to few(counter churn-threshold)/single.
    // Currently this can result in incoming spam of gossip history from everyone.
    // Can also just be a single target once node-ageing makes Offline votes Opaque which should
    // remove invalid test failures for unaccumulated parsec::Remove blocks.
    fn send_parsec_poke(&mut self) {
        let version = self.gen_pfx_info.parsec_version;
        let recipients = self
            .gen_pfx_info
            .latest_info
            .member_nodes()
            .filter(|node| node.public_id() != self.id())
            .map(P2pNode::connection_info)
            .cloned()
            .collect_vec();

        debug!(
            "{} Sending Parsec Poke for version {} to {:?}",
            self, version, recipients
        );

        for recipient in recipients {
            trace!("{} send poke to {:?}", self, recipient);
            self.send_direct_message(&recipient, DirectMessage::ParsecPoke(version));
        }
    }

    // Backlog the message to be processed once we are established.
    fn add_message_to_backlog(&mut self, msg: SignedRoutingMessage) {
        trace!(
            "{} Not elder yet. Delaying message handling: {:?}",
            self,
            msg
        );
        self.routing_msg_backlog.push(msg)
    }

    fn handle_relocate(&mut self, details: SignedRelocateDetails) -> Transition {
        if details.content().pub_id != *self.id() {
            // This `Relocate` message is not for us - it's most likely a duplicate of a previous
            // message that we already handled.
            return Transition::Stay;
        }

        debug!(
            "{} - Received Relocate message to join the section at {}.",
            self,
            details.content().destination
        );

        if !self.check_signed_relocation_details(&details) {
            return Transition::Stay;
        }

        let conn_infos: Vec<_> = self
            .chain
            .our_elders()
            .map(|p2p_node| p2p_node.connection_info().clone())
            .collect();

        self.network_service_mut().remove_and_disconnect_all();

        Transition::Relocate {
            details,
            conn_infos,
        }
    }

    // Since we are an adult we will only give info about our section elders and they will further
    // guide the joining node.
    fn handle_bootstrap_request(&mut self, p2p_node: P2pNode, destination: XorName) {
        self.respond_to_bootstrap_request(&p2p_node, &destination);
    }

    fn respond_to_bootstrap_request(&mut self, p2p_node: &P2pNode, name: &XorName) {
        let response = if self.our_prefix().matches(name) {
            debug!("{} - Sending BootstrapResponse::Join to {}", self, p2p_node);
            BootstrapResponse::Join(self.chain.our_info().clone())
        } else {
            let conn_infos: Vec<_> = self
                .closest_known_elders_to(name)
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
            DirectMessage::BootstrapResponse(response),
        );
    }

    fn handle_genesis_update(
        &mut self,
        gen_pfx_info: GenesisPfxInfo,
    ) -> Result<Transition, RoutingError> {
        // An Adult can receive the same message from multiple Elders - bail early if we are
        // already up to date
        if gen_pfx_info == self.gen_pfx_info {
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
        Ok(Transition::Stay)
    }

    // Send signed_msg to our elders so they can route it properly.
    fn send_signed_message_to_elders(
        &mut self,
        signed_msg: &SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        trace!(
            "{}: Forwarding message {:?} via elder targets {:?}",
            self,
            signed_msg,
            self.chain.our_elders().format(", ")
        );

        let routing_msg_filter = &mut self.routing_msg_filter;
        let targets: Vec<_> = self
            .chain
            .our_elders()
            .filter(|p2p_node| {
                routing_msg_filter
                    .filter_outgoing(signed_msg.routing_message(), p2p_node.public_id())
                    .is_new()
            })
            .map(|node| node.connection_info().clone())
            .collect();

        let message = self.to_hop_message(signed_msg.clone())?;
        self.send_message_to_targets(&targets, targets.len(), message);

        // we've seen this message - don't handle it again if someone else sends it to us
        let _ = self
            .routing_msg_filter
            .filter_incoming(signed_msg.routing_message());

        Ok(())
    }

    /// Handles a signature of a `SignedMessage`, and if we have enough to verify the signed
    /// message, handles it.
    fn handle_message_signature(
        &mut self,
        msg: SignedRoutingMessage,
        pub_id: PublicId,
    ) -> Result<(), RoutingError> {
        if !self.chain.is_peer_elder(&pub_id) {
            debug!(
                "{} - Received message signature from not known elder (still use it) {}, {:?}",
                self, pub_id, msg
            );
        }

        if let Some(signed_msg) = self.sig_accumulator.add_proof(msg.clone()) {
            self.handle_signed_message(signed_msg)?;
        }
        Ok(())
    }

    // If the message is for us, verify it then, handle the enclosed routing message and swarm it
    // to the rest of our section when destination is targeting multiple; if not, forward it.
    fn handle_signed_message(
        &mut self,
        signed_msg: SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        if !self
            .routing_msg_filter
            .filter_incoming(signed_msg.routing_message())
            .is_new()
        {
            trace!(
                "{} Known message: {:?} - not handling further",
                self,
                signed_msg.routing_message()
            );
            return Ok(());
        }

        self.handle_filtered_signed_message(signed_msg)
    }

    fn handle_filtered_signed_message(
        &mut self,
        signed_msg: SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        trace!(
            "{} - Handle signed message: {:?}",
            self,
            signed_msg.routing_message()
        );

        if self.in_authority(&signed_msg.routing_message().dst) {
            self.check_signed_message_integrity(&signed_msg)?;
            self.routing_msg_backlog.push(signed_msg.clone());
        }

        self.send_signed_message_to_elders(&signed_msg)?;
        Ok(())
    }
}

#[cfg(feature = "mock_base")]
impl Adult {
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
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

    fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        self.chain.in_authority(auth)
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

    fn finish_handle_transition(&mut self, outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - State changed to Adult finished.", self);

        for msg in mem::replace(&mut self.routing_msg_backlog, Default::default()) {
            if let Err(err) = self.dispatch_routing_message(msg, outbox) {
                debug!("{} - {:?}", self, err);
            }
        }

        let mut transition = Transition::Stay;
        for (pub_id, msg) in mem::replace(&mut self.direct_msg_backlog, Default::default()) {
            if let Transition::Stay = &transition {
                match self.handle_direct_message(msg, pub_id, outbox) {
                    Ok(new_transition) => transition = new_transition,
                    Err(err) => debug!("{} - {:?}", self, err),
                }
            } else {
                self.direct_msg_backlog.push((pub_id, msg));
            }
        }

        transition
    }

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        if self.parsec_timer_token == token {
            self.send_parsec_poke();
            self.parsec_timer_token = self.timer.schedule(POKE_TIMEOUT);
        }

        Transition::Stay
    }

    fn handle_peer_lost(&mut self, peer_addr: SocketAddr, _: &mut dyn EventBox) -> Transition {
        debug!("{} - Lost peer {}", self, peer_addr);
        Transition::Stay
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        p2p_node: P2pNode,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::messages::DirectMessage::*;
        match msg {
            MessageSignature(msg) => {
                self.handle_message_signature(msg, *p2p_node.public_id())?;
                Ok(Transition::Stay)
            }
            ParsecRequest(version, par_request) => {
                self.handle_parsec_request(version, par_request, p2p_node, outbox)
            }
            ParsecResponse(version, par_response) => {
                self.handle_parsec_response(version, par_response, *p2p_node.public_id(), outbox)
            }
            BootstrapRequest(name) => {
                self.handle_bootstrap_request(p2p_node, name);
                Ok(Transition::Stay)
            }
            ConnectionResponse => {
                debug!("{} - Received connection response from {}", self, p2p_node);
                Ok(Transition::Stay)
            }
            GenesisUpdate(gen_pfx_info) => self.handle_genesis_update(gen_pfx_info),
            Relocate(details) => Ok(self.handle_relocate(details)),
            msg @ BootstrapResponse(_) => {
                debug!(
                    "{} Unhandled direct message from {}, discard: {:?}",
                    self,
                    p2p_node.public_id(),
                    msg
                );
                Ok(Transition::Stay)
            }
            msg @ JoinRequest(_) | msg @ ParsecPoke(_) => {
                debug!(
                    "{} Unhandled direct message from {}, adding to backlog: {:?}",
                    self,
                    p2p_node.public_id(),
                    msg
                );
                self.direct_msg_backlog.push((p2p_node, msg));
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let HopMessage { content: msg, .. } = msg;
        self.handle_signed_message(msg)?;
        Ok(Transition::Stay)
    }

    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        if self.in_authority(&routing_msg.dst) {
            return Ok(()); // Message is for us.
        }

        let signed_msg = SignedRoutingMessage::single_source(routing_msg, self.full_id())?;
        self.send_signed_message_to_elders(&signed_msg)?;
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

    fn handle_online_event(
        &mut self,
        payload: OnlinePayload,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_add_member(payload.p2p_node.public_id()) {
            info!("{} - ignore Online: {:?}.", self, payload);
        } else {
            info!("{} - handle Online: {:?}.", self, payload);

            let pub_id = *payload.p2p_node.public_id();
            self.chain.add_member(payload.p2p_node, payload.age);
            self.chain.increment_age_counters(&pub_id);

            // FIXME: send appropriate events
            // self.send_event(Event::NodeAdded(*pub_id.name()), outbox);
        }

        Ok(())
    }

    fn handle_offline_event(
        &mut self,
        pub_id: PublicId,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_remove_member(&pub_id) {
            info!("{} - ignore Offline: {}.", self, pub_id);
        } else {
            info!("{} - handle Offline: {}.", self, pub_id);

            self.chain.increment_age_counters(&pub_id);
            self.chain.remove_member(&pub_id);
            self.disconnect_by_id_lookup(&pub_id);

            // FIXME: send appropriate events
            // self.send_event(Event::NodeLost(*pub_id.name()), outbox);
        }

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

    fn handle_relocate_event(
        &mut self,
        details: RelocateDetails,
        _signature: BlsSignature,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_remove_member(&details.pub_id) {
            info!("{} - ignore Relocate: {:?} - not a member", self, details);
            return Ok(());
        }

        info!("{} - handle Relocate: {:?}.", self, details);
        self.chain.remove_member(&details.pub_id);
        self.disconnect_by_id_lookup(&details.pub_id);

        Ok(())
    }

    fn handle_relocate_prepare_event(
        &mut self,
        _payload: RelocateDetails,
        _count_down: i32,
        _outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        Ok(())
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

    fn handle_prune(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled ParsecPrune event", self);
        Ok(())
    }
}

impl Display for Adult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Adult({}({:b}))", self.name(), self.our_prefix())
    }
}
