// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "mock_parsec"))]
mod tests;

use super::{
    common::{Approved, Base},
    BootstrappingPeer,
};
use crate::{
    chain::{
        delivery_group_size, AccumulatingEvent, AckMessagePayload, Chain, DevParams, EldersChange,
        EldersInfo, EventSigPayload, GenesisPfxInfo, IntoAccumulatingEvent, NetworkEvent,
        NetworkParams, OnlinePayload, ParsecResetData, PrefixChange, SectionKeyInfo,
        SendAckMessagePayload, MIN_AGE, MIN_AGE_COUNTER,
    },
    crypto::Digest256,
    error::{BootstrapResponseError, InterfaceError, RoutingError},
    event::Event,
    id::{FullId, P2pNode, PublicId},
    messages::{
        BootstrapResponse, DirectMessage, HopMessage, MessageContent, RoutingMessage,
        SignedRoutingMessage,
    },
    outbox::EventBox,
    parsec::{self, DkgResultWrapper, ParsecMap},
    pause::PausedState,
    peer_map::PeerMap,
    relocation::{RelocateDetails, RelocatePayload, SignedRelocateDetails},
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix, Xorable},
    signature_accumulator::SignatureAccumulator,
    state_machine::State,
    state_machine::Transition,
    time::Duration,
    timer::Timer,
    xor_name::XorName,
    BlsPublicKeySet, BlsSignature, ConnectionInfo, NetworkService,
};
use itertools::Itertools;
use log::LogLevel;
use serde::Serialize;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::{self, Display, Formatter},
    iter, mem,
};

#[cfg(feature = "mock_base")]
use {crate::messages::Message, std::net::SocketAddr};

/// Time after which a `Ticked` event is sent.
const TICK_TIMEOUT: Duration = Duration::from_secs(15);
const GOSSIP_TIMEOUT: Duration = Duration::from_secs(2);

pub struct ElderDetails {
    pub chain: Chain,
    pub network_service: NetworkService,
    pub event_backlog: Vec<Event>,
    pub full_id: FullId,
    pub gen_pfx_info: GenesisPfxInfo,
    pub msg_queue: VecDeque<SignedRoutingMessage>,
    pub routing_msg_backlog: Vec<SignedRoutingMessage>,
    pub direct_msg_backlog: Vec<(P2pNode, DirectMessage)>,
    pub parsec_map: ParsecMap,
    pub peer_map: PeerMap,
    pub routing_msg_filter: RoutingMessageFilter,
    pub timer: Timer,
}

pub struct Elder {
    network_service: NetworkService,
    full_id: FullId,
    is_first_node: bool,
    // The queue of routing messages addressed to us. These do not themselves need forwarding,
    // although they may wrap a message which needs forwarding.
    msg_queue: VecDeque<SignedRoutingMessage>,
    routing_msg_backlog: Vec<SignedRoutingMessage>,
    direct_msg_backlog: Vec<(P2pNode, DirectMessage)>,
    peer_map: PeerMap,
    routing_msg_filter: RoutingMessageFilter,
    sig_accumulator: SignatureAccumulator,
    tick_timer_token: u64,
    timer: Timer,
    parsec_map: ParsecMap,
    gen_pfx_info: GenesisPfxInfo,
    gossip_timer_token: u64,
    chain: Chain,
    pfx_is_successfully_polled: bool,
    /// DKG cache
    dkg_cache: BTreeMap<BTreeSet<PublicId>, EldersInfo>,
}

impl Elder {
    pub fn first(
        mut network_service: NetworkService,
        full_id: FullId,
        network_cfg: NetworkParams,
        timer: Timer,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let public_id = *full_id.public_id();
        let connection_info = network_service.our_connection_info()?;
        let p2p_node = P2pNode::new(public_id, connection_info);
        let mut first_ages = BTreeMap::new();
        let _ = first_ages.insert(public_id, MIN_AGE_COUNTER);
        let gen_pfx_info = GenesisPfxInfo {
            first_info: create_first_elders_info(p2p_node)?,
            first_state_serialized: Vec::new(),
            first_ages,
            latest_info: EldersInfo::default(),
        };
        let parsec_map = ParsecMap::new(full_id.clone(), &gen_pfx_info);
        let chain = Chain::new(
            network_cfg,
            DevParams::default(),
            public_id,
            gen_pfx_info.clone(),
        );
        let peer_map = PeerMap::new();

        let details = ElderDetails {
            chain,
            network_service,
            event_backlog: Vec::new(),
            full_id,
            gen_pfx_info,
            msg_queue: Default::default(),
            routing_msg_backlog: Default::default(),
            direct_msg_backlog: Default::default(),
            parsec_map,
            peer_map,
            routing_msg_filter: RoutingMessageFilter::new(),
            timer,
        };

        let node = Self::new(details, true, Default::default());

        debug!("{} - State changed to Node.", node);
        info!("{} - Started a new network as a seed node.", node);

        outbox.send_event(Event::Connected);

        Ok(node)
    }

    pub fn from_adult(
        mut details: ElderDetails,
        elders_info: EldersInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let event_backlog = mem::replace(&mut details.event_backlog, Vec::new());
        let mut elder = Self::new(details, false, Default::default());
        elder.init(elders_info, old_pfx, event_backlog, outbox)?;
        Ok(elder)
    }

    pub fn pause(self) -> Result<PausedState, RoutingError> {
        Ok(PausedState {
            chain: self.chain,
            full_id: self.full_id,
            gen_pfx_info: self.gen_pfx_info,
            msg_filter: self.routing_msg_filter,
            msg_queue: self.msg_queue,
            network_service: self.network_service,
            network_rx: None,
            parsec_map: self.parsec_map,
            peer_map: self.peer_map,
            sig_accumulator: self.sig_accumulator,
        })
    }

    pub fn resume(state: PausedState, timer: Timer) -> Self {
        Self::new(
            ElderDetails {
                chain: state.chain,
                network_service: state.network_service,
                event_backlog: Vec::new(),
                full_id: state.full_id,
                gen_pfx_info: state.gen_pfx_info,
                msg_queue: state.msg_queue,
                routing_msg_backlog: Default::default(),
                direct_msg_backlog: Default::default(),
                parsec_map: state.parsec_map,
                peer_map: state.peer_map,
                routing_msg_filter: state.msg_filter,
                timer,
            },
            false,
            state.sig_accumulator,
        )
    }

    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.chain.our_elders()
    }

    pub fn relocate(
        self,
        conn_infos: Vec<ConnectionInfo>,
        details: SignedRelocateDetails,
    ) -> Result<State, RoutingError> {
        Ok(State::BootstrappingPeer(BootstrappingPeer::relocate(
            self.network_service,
            self.full_id,
            self.chain.network_cfg(),
            self.timer,
            conn_infos,
            details,
            self.chain.dev_params().clone(),
        )))
    }

    fn new(
        details: ElderDetails,
        is_first_node: bool,
        sig_accumulator: SignatureAccumulator,
    ) -> Self {
        let timer = details.timer;
        let tick_timer_token = timer.schedule(TICK_TIMEOUT);
        let gossip_timer_token = timer.schedule(GOSSIP_TIMEOUT);

        Self {
            network_service: details.network_service,
            full_id: details.full_id.clone(),
            is_first_node,
            msg_queue: details.msg_queue,
            routing_msg_backlog: details.routing_msg_backlog,
            direct_msg_backlog: details.direct_msg_backlog,
            peer_map: details.peer_map,
            routing_msg_filter: details.routing_msg_filter,
            sig_accumulator,
            tick_timer_token,
            timer: timer,
            parsec_map: details.parsec_map,
            gen_pfx_info: details.gen_pfx_info,
            gossip_timer_token,
            chain: details.chain,
            pfx_is_successfully_polled: false,
            dkg_cache: Default::default(),
        }
    }

    fn print_rt_size(&self) {
        const TABLE_LVL: LogLevel = LogLevel::Info;
        if log_enabled!(TABLE_LVL) {
            let status_str = format!(
                "{} - Routing Table size: {:3}",
                self,
                self.chain.elders().count()
            );
            let network_estimate = match self.chain.network_size_estimate() {
                (n, true) => format!("Exact network size: {}", n),
                (n, false) => format!("Estimated network size: {}", n),
            };
            let sep_len = cmp::max(status_str.len(), network_estimate.len());
            let sep_str = iter::repeat('-').take(sep_len).collect::<String>();
            log!(target: "routing_stats", TABLE_LVL, " -{}- ", sep_str);
            log!(target: "routing_stats", TABLE_LVL, "| {:<1$} |", status_str, sep_len);
            log!(target: "routing_stats", TABLE_LVL, "| {:<1$} |", network_estimate, sep_len);
            log!(target: "routing_stats", TABLE_LVL, " -{}- ", sep_str);
        }
    }

    // Initialise regular node
    fn init(
        &mut self,
        elders_info: EldersInfo,
        old_pfx: Prefix<XorName>,
        event_backlog: Vec<Event>,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        debug!("{} - State changed to Elder.", self);
        trace!(
            "{} - Node Established. Prefixes: {:?}",
            self,
            self.chain.prefixes()
        );

        // Send `Event::Connected` first and then any backlogged events from previous states.
        for event in iter::once(Event::Connected).chain(event_backlog) {
            self.send_event(event, outbox);
        }

        // Handle the SectionInfo event which triggered us becoming established node.
        let neighbour_change = EldersChange {
            added: self.chain.neighbour_elder_nodes().cloned().collect(),
            removed: Default::default(),
        };
        let _ = self.handle_section_info_event(elders_info, old_pfx, neighbour_change, outbox)?;

        Ok(())
    }

    fn handle_routing_messages(&mut self, outbox: &mut dyn EventBox) -> Transition {
        while let Some(msg) = self.msg_queue.pop_front() {
            if self.in_authority(&msg.routing_message().dst) {
                match self.dispatch_routing_message(msg, outbox) {
                    Ok(Transition::Stay) => (),
                    Ok(transition) => return transition,
                    Err(err) => debug!("{} Routing message dispatch failed: {:?}", self, err),
                }
            }
        }

        Transition::Stay
    }

    fn public_key_set(&self) -> BlsPublicKeySet {
        self.chain.public_key_set()
    }

    fn handle_parsec_poke(&mut self, msg_version: u64, pub_id: PublicId) {
        self.send_parsec_gossip(Some((msg_version, pub_id)))
    }

    /// Votes for `Merge` if necessary, or for the merged `SectionInfo` if both siblings have
    /// already accumulated `Merge`.
    fn merge_if_necessary(&mut self) -> Result<(), RoutingError> {
        let sibling_pfx = self.our_prefix().sibling();
        if self.chain.is_self_merge_ready() && self.chain.other_prefixes().contains(&sibling_pfx) {
            let payload = *self.chain.our_info().hash();
            let src = Authority::PrefixSection(*self.our_prefix());
            let dst = Authority::PrefixSection(sibling_pfx);
            let content = MessageContent::Merge(payload);
            if let Err(err) = self.send_routing_message(RoutingMessage { src, dst, content }) {
                debug!("{} Failed to send Merge: {:?}.", self, err);
            }
        }
        if let Some(merged_info) = self.chain.try_merge()? {
            self.vote_for_signed_event(merged_info)?;
        } else if self.chain.should_vote_for_merge() && !self.chain.is_self_merge_ready() {
            self.vote_for_event(AccumulatingEvent::OurMerge);
        }
        Ok(())
    }

    // Connect to all neighbour elders we are not yet connected to and disconnect from peers that are no
    // longer members of our section or elders of neighbour sections.
    fn update_neighbour_connections(&mut self, change: EldersChange, _outbox: &mut dyn EventBox) {
        if self.chain.prefix_change() == PrefixChange::None {
            for p2p_node in change.removed {
                // The peer might have been relocated from a neighbour to us - in that case do not
                // disconnect from them.
                if self.chain.is_peer_our_member(p2p_node.public_id()) {
                    continue;
                }

                self.disconnect(p2p_node.public_id());
            }
        }

        for p2p_node in change.added {
            let pub_id = *p2p_node.public_id();
            if !self.peer_map.has(&pub_id) {
                self.peer_map
                    .insert(pub_id, p2p_node.connection_info().clone());
                self.send_direct_message(&pub_id, DirectMessage::ConnectionResponse);
            };
        }

        let to_connect: Vec<_> = self
            .chain
            .our_elders()
            .filter(|p2p_node| !self.peer_map.has(p2p_node.public_id()))
            .cloned()
            .collect();

        for p2p_node in to_connect.into_iter() {
            let pub_id = p2p_node.public_id();
            self.peer_map
                .insert(*pub_id, p2p_node.connection_info().clone());
            self.send_direct_message(pub_id, DirectMessage::ConnectionResponse);
        }
    }

    fn reset_parsec_with_data(&mut self, reset_data: ParsecResetData) -> Result<(), RoutingError> {
        let drained_obs: Vec<_> = self
            .parsec_map
            .our_unpolled_observations()
            .cloned()
            .collect();

        let ParsecResetData {
            gen_pfx_info,
            mut cached_events,
            completed_events,
        } = reset_data;
        self.gen_pfx_info = gen_pfx_info;
        self.init_parsec(); // We don't reset the chain on prefix change.

        for obs in drained_obs {
            let event = match obs {
                parsec::Observation::OpaquePayload(event) => event,

                parsec::Observation::Genesis { .. }
                | parsec::Observation::Add { .. }
                | parsec::Observation::Remove { .. }
                | parsec::Observation::Accusation { .. }
                | parsec::Observation::StartDkg(_)
                | parsec::Observation::DkgResult { .. }
                | parsec::Observation::DkgMessage(_) => continue,
            };
            let _ = cached_events.insert(event);
        }
        let our_pfx = *self.chain.our_prefix();

        cached_events
            .iter()
            .filter(|event| match event.payload {
                // Only re-vote not yet accumulated events and still relevant to our new prefix.
                AccumulatingEvent::Offline(pub_id) => {
                    our_pfx.matches(pub_id.name()) && !completed_events.contains(&event.payload)
                }
                AccumulatingEvent::AckMessage(ref payload) => {
                    our_pfx.matches(&payload.dst_name) && !completed_events.contains(&event.payload)
                }

                // Drop: no longer relevant after prefix change.
                // TODO: verify this is really the case. Some/all of these might still make sense
                // to carry over. In case it does not, add a comment explaining why.
                AccumulatingEvent::Online(_)
                | AccumulatingEvent::StartDkg(_)
                | AccumulatingEvent::ParsecPrune
                | AccumulatingEvent::Relocate(_) => false,

                // Keep: Additional signatures for neighbours for sec-msg-relay.
                AccumulatingEvent::SectionInfo(ref elders_info)
                | AccumulatingEvent::NeighbourInfo(ref elders_info) => {
                    our_pfx.is_neighbour(elders_info.prefix())
                }

                // Drop: condition may have changed.
                AccumulatingEvent::OurMerge => false,

                // Keep: Still relevant after prefix change.
                AccumulatingEvent::NeighbourMerge(_)
                | AccumulatingEvent::TheirKeyInfo(_)
                | AccumulatingEvent::SendAckMessage(_)
                | AccumulatingEvent::User(_) => true,
            })
            .for_each(|event| {
                self.vote_for_network_event(event.clone());
            });

        Ok(())
    }

    fn reset_parsec(&mut self) -> Result<(), RoutingError> {
        let reset_data = self.chain.prepare_parsec_reset()?;
        self.reset_parsec_with_data(reset_data)
    }

    fn finalise_prefix_change(&mut self) -> Result<(), RoutingError> {
        let reset_data = self.chain.finalise_prefix_change()?;
        self.reset_parsec_with_data(reset_data)
    }

    fn send_neighbour_infos(&mut self) {
        self.chain.other_prefixes().iter().for_each(|pfx| {
            let src = Authority::Section(self.our_prefix().name());
            let dst = Authority::PrefixSection(*pfx);
            let content = MessageContent::NeighbourInfo(self.chain.our_info().clone());

            if let Err(err) = self.send_routing_message(RoutingMessage { src, dst, content }) {
                debug!("{} Failed to send NeighbourInfo: {:?}.", self, err);
            }
        });
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
                "{} - Received message signature from invalid peer {}, {:?}",
                self, pub_id, msg
            );
            return Err(RoutingError::InvalidSource);
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
        mut signed_msg: SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        if self.in_authority(&signed_msg.routing_message().dst) {
            self.check_signed_message_trust(&signed_msg)?;
            self.check_signed_message_integrity(&signed_msg)?;
            self.update_our_knowledge(&signed_msg);

            if signed_msg.routing_message().dst.is_multiple() {
                // Broadcast to the rest of the section.
                if let Err(error) = self.send_signed_message(&mut signed_msg) {
                    debug!("{} Failed to send {:?}: {:?}", self, signed_msg, error);
                }
            }
            // if addressed to us, then we just queue it and return
            self.msg_queue.push_back(signed_msg);
        } else if let Err(error) = self.send_signed_message(&mut signed_msg) {
            debug!("{} Failed to send {:?}: {:?}", self, signed_msg, error);
        }

        Ok(())
    }

    fn dispatch_routing_message(
        &mut self,
        signed_msg: SignedRoutingMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::messages::MessageContent::*;

        let (msg, _) = signed_msg.into_parts();

        match msg.content {
            UserMessage { .. } => (),
            _ => trace!("{} Got routing message {:?}.", self, msg),
        }

        match (msg.content, msg.src, msg.dst) {
            (
                ConnectionRequest {
                    conn_info, pub_id, ..
                },
                src @ Authority::Node(_),
                dst @ Authority::Node(_),
            ) => {
                self.handle_connection_request(conn_info, pub_id, src, dst, outbox)?;
                Ok(Transition::Stay)
            }
            (NeighbourInfo(elders_info), Authority::Section(_), Authority::PrefixSection(_)) => {
                self.handle_neighbour_info(elders_info)?;
                Ok(Transition::Stay)
            }
            (Merge(digest), Authority::PrefixSection(_), Authority::PrefixSection(_)) => {
                self.handle_merge(digest)?;
                Ok(Transition::Stay)
            }
            (UserMessage(content), src, dst) => {
                outbox.send_event(Event::MessageReceived { content, src, dst });
                Ok(Transition::Stay)
            }
            (
                AckMessage {
                    src_prefix,
                    ack_version,
                },
                Authority::Section(src),
                Authority::Section(dst),
            ) => {
                self.handle_ack_message(src_prefix, ack_version, src, dst)?;
                Ok(Transition::Stay)
            }
            (content, src, dst) => {
                debug!(
                    "{} Unhandled routing message {:?} from {:?} to {:?}",
                    self, content, src, dst
                );
                Err(RoutingError::BadAuthority)
            }
        }
    }

    fn handle_ack_message(
        &mut self,
        src_prefix: Prefix<XorName>,
        ack_version: u64,
        _src: XorName,
        dst: XorName,
    ) -> Result<(), RoutingError> {
        // Prefix doesn't need to match, as we may get an ack for the section where we were before
        // splitting.
        self.vote_for_event(AccumulatingEvent::AckMessage(AckMessagePayload {
            dst_name: dst,
            src_prefix,
            ack_version,
        }));
        Ok(())
    }

    fn vote_send_section_info_ack(&mut self, ack_payload: SendAckMessagePayload) {
        let has_their_keys = self.chain.get_their_keys_info().any(|(_, info)| {
            *info.prefix() == ack_payload.ack_prefix && *info.version() == ack_payload.ack_version
        });

        if has_their_keys {
            self.vote_for_event(AccumulatingEvent::SendAckMessage(ack_payload));
        }
    }

    // Send NodeApproval to the current candidate which promotes them to Adult and allows them to
    // passively participate in parsec consensus (that is, they can receive gossip and poll
    // consensused blocks out of parsec, but they can't vote yet)
    fn handle_candidate_approval(&mut self, p2p_node: P2pNode, _outbox: &mut dyn EventBox) {
        info!(
            "{} Our section with {:?} has approved candidate {}.",
            self,
            self.our_prefix(),
            p2p_node
        );

        let pub_id = *p2p_node.public_id();
        let dst = Authority::Node(*pub_id.name());

        // Make sure we are connected to the candidate
        if !self.peer_map.has(&pub_id) {
            trace!(
                "{} - Not yet connected to {} - use p2p_node.",
                self,
                p2p_node
            );
            self.peer_map
                .insert(pub_id, p2p_node.connection_info().clone());
            self.send_direct_message(&pub_id, DirectMessage::ConnectionResponse);
        };

        let trimmed_info = GenesisPfxInfo {
            first_info: self.gen_pfx_info.first_info.clone(),
            first_state_serialized: Default::default(),
            first_ages: self.gen_pfx_info.first_ages.clone(),
            latest_info: self.chain.our_info().clone(),
        };

        let src = Authority::PrefixSection(*trimmed_info.first_info.prefix());
        let content = MessageContent::NodeApproval(trimmed_info);
        if let Err(error) = self.send_routing_message(RoutingMessage { src, dst, content }) {
            debug!(
                "{} Failed sending NodeApproval to {}: {:?}",
                self, pub_id, error
            );
        }
    }

    fn init_parsec(&mut self) {
        self.set_pfx_successfully_polled(false);
        self.parsec_map
            .init(self.full_id.clone(), &self.gen_pfx_info, &self.log_ident())
    }

    // If this returns an error, the peer will be dropped.
    fn handle_bootstrap_request(
        &mut self,
        pub_id: PublicId,
        name: XorName,
    ) -> Result<(), RoutingError> {
        debug!(
            "{} - Received BootstrapRequest to section at {} from {:?}.",
            self, name, pub_id
        );

        if !self.peer_map.has(&pub_id) {
            log_or_panic!(
                LogLevel::Error,
                "Not connected to the sender of BootstrapRequest."
            );
            // Note: peer_map and this block is scheduled for removal
            return Err(RoutingError::PeerNotFound(pub_id));
        };

        if self.chain.is_peer_our_member(&pub_id) {
            debug!(
                "{} - Ignoring BootstrapRequest from {} - already member of our section",
                self, pub_id
            );
            return Ok(());
        }

        // Check min section size.
        if !self.is_first_node && self.chain.len() < self.chain.elder_size() - 1 {
            debug!(
                "{} - Peer {:?} rejected: Routing table has {} entries. {} required.",
                self,
                pub_id,
                self.chain.len(),
                self.chain.elder_size() - 1
            );
            self.send_direct_message(
                &pub_id,
                DirectMessage::BootstrapResponse(BootstrapResponse::Error(
                    BootstrapResponseError::TooFewPeers,
                )),
            );
            self.disconnect(&pub_id);
            return Ok(());
        }

        self.respond_to_bootstrap_request(&pub_id, &name);

        Ok(())
    }

    fn respond_to_bootstrap_request(&mut self, pub_id: &PublicId, name: &XorName) {
        let response = if self.our_prefix().matches(name) {
            debug!("{} - Sending BootstrapResponse::Join to {}", self, pub_id);

            BootstrapResponse::Join {
                prefix: *self.chain.our_prefix(),
                p2p_nodes: self.chain.our_elders().cloned().collect(),
            }
        } else {
            let names = self.chain.closest_section(name).1;
            let conn_infos = self
                .peer_map
                .get_connection_infos(&names)
                .cloned()
                .collect();
            debug!(
                "{} - Sending BootstrapResponse::Rebootstrap to {}",
                self, pub_id
            );
            BootstrapResponse::Rebootstrap(conn_infos)
        };
        self.send_direct_message(pub_id, DirectMessage::BootstrapResponse(response));
    }

    fn handle_connection_response(&mut self, pub_id: PublicId, _: &mut dyn EventBox) {
        debug!("{} - Received connection response from {}", self, pub_id);
    }

    fn handle_join_request(
        &mut self,
        p2p_node: P2pNode,
        relocate_payload: Option<RelocatePayload>,
    ) {
        debug!("{} - Received JoinRequest from {}", self, p2p_node);

        let pub_id = *p2p_node.public_id();
        if !self.chain.our_prefix().matches(pub_id.name()) {
            debug!(
                "{} - Ignoring JoinRequest from {} - name doesn't match our prefix {:?}.",
                self,
                pub_id,
                self.chain.our_prefix()
            );
            return;
        }

        if self.chain.is_peer_our_member(&pub_id) {
            debug!(
                "{} - Ignoring JoinRequest from {} - already member of our section.",
                self, pub_id
            );
            return;
        }

        // This joining node is being relocated to us.
        let age = if let Some(payload) = relocate_payload {
            if !payload.verify_identity(&pub_id) {
                debug!(
                    "{} - Ignoring relocation JoinRequest from {} - invalid signature.",
                    self, pub_id
                );
                return;
            }

            let details = payload.details;

            if !self
                .chain
                .our_prefix()
                .matches(&details.content().destination)
            {
                debug!(
                    "{} - Ignoring relocation JoinRequest from {} - destination {} doesn't match our prefix {:?}.",
                    self, pub_id, details.content().destination, self.chain.our_prefix()
                );
                return;
            }

            if !self.check_signed_relocation_details(&details) {
                return;
            }

            details.content().age
        } else {
            MIN_AGE
        };

        self.send_direct_message(&pub_id, DirectMessage::ConnectionResponse);
        self.vote_for_event(AccumulatingEvent::Online(OnlinePayload { p2p_node, age }))
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

        let names = self.chain.closest_section(&details.content().destination).1;
        let conn_infos = self
            .peer_map
            .get_connection_infos(&names)
            .cloned()
            .collect();

        for conn_info in self.peer_map.remove_all() {
            self.network_service
                .service_mut()
                .disconnect_from(conn_info.peer_addr);
        }

        Transition::Relocate {
            details,
            conn_infos,
        }
    }

    fn update_our_knowledge(&mut self, signed_msg: &SignedRoutingMessage) {
        let key_info = if let Some(key_info) = signed_msg.source_section_key_info() {
            key_info
        } else {
            return;
        };

        let new_key_info = self
            .chain
            .get_their_keys_info()
            .find(|(prefix, _)| prefix.is_compatible(key_info.prefix()))
            .map_or(false, |(_, info)| *info.version() < *key_info.version());

        if new_key_info {
            self.vote_for_event(AccumulatingEvent::TheirKeyInfo(key_info.clone()));
        }
    }

    fn handle_neighbour_info(&mut self, elders_info: EldersInfo) -> Result<(), RoutingError> {
        if self.chain.is_new_neighbour(&elders_info) {
            self.vote_for_event(AccumulatingEvent::NeighbourInfo(elders_info));
        } else {
            trace!(
                "{} Ignore not new neighbour neighbour_info: {:?}",
                self,
                elders_info
            );
        }
        Ok(())
    }

    fn handle_merge(&mut self, digest: Digest256) -> Result<(), RoutingError> {
        self.vote_for_event(AccumulatingEvent::NeighbourMerge(digest));
        Ok(())
    }

    fn maintain_parsec(&mut self) {
        if self.parsec_map.needs_pruning() {
            self.vote_for_event(AccumulatingEvent::ParsecPrune);
            self.parsec_map_mut().set_pruning_voted_for();
        }
    }

    fn vote_for_event(&mut self, event: AccumulatingEvent) {
        self.vote_for_network_event(event.into_network_event())
    }

    fn vote_for_relocate(&mut self, details: RelocateDetails) -> Result<(), RoutingError> {
        self.vote_for_signed_event(details)
    }

    fn vote_for_section_info(&mut self, elders_info: EldersInfo) -> Result<(), RoutingError> {
        self.vote_for_signed_event(elders_info)
    }

    fn vote_for_signed_event<T: IntoAccumulatingEvent + Serialize>(
        &mut self,
        payload: T,
    ) -> Result<(), RoutingError> {
        let signature_payload = EventSigPayload::new(&self.full_id, &payload)?;
        let event = payload
            .into_accumulating_event()
            .into_network_event_with(Some(signature_payload));
        self.vote_for_network_event(event);
        Ok(())
    }

    fn vote_for_network_event(&mut self, event: NetworkEvent) {
        trace!("{} Vote for Event {:?}", self, event);
        self.parsec_map.vote_for(event, &self.log_ident())
    }

    // ----- Send Functions -----------------------------------------------------------------------
    fn send_user_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: Vec<u8>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message(RoutingMessage {
            src,
            dst,
            content: MessageContent::UserMessage(content),
        })
    }

    // Send signed_msg on route. Hop is the name of the peer we received this from, or our name if
    // we are the first sender or the proxy for a client or joining node.
    fn send_signed_message(
        &mut self,
        signed_msg: &mut SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        let dst = signed_msg.routing_message().dst;

        // If the message is to a single node and we have the connection info for this node, don't
        // go through the routing table
        let single_target = if let Authority::Node(node_name) = dst {
            self.peer_map.get_id(&node_name)
        } else {
            None
        };

        let (target_pub_ids, dg_size) = if let Some(target) = single_target {
            (vec![*target], 1)
        } else {
            self.get_targets(signed_msg.routing_message())?
        };

        trace!(
            "{}: Sending message {:?} via targets {:?}",
            self,
            signed_msg,
            target_pub_ids
        );

        let targets: Vec<_> = target_pub_ids
            .into_iter()
            .filter(|pub_id| {
                self.routing_msg_filter
                    .filter_outgoing(signed_msg.routing_message(), pub_id)
                    .is_new()
            })
            .collect();

        let message = self.to_hop_message(signed_msg.clone())?;
        self.send_message_to_targets(&targets, dg_size, message);

        // we've seen this message - don't handle it again if someone else sends it to us
        let _ = self
            .routing_msg_filter
            .filter_incoming(signed_msg.routing_message());

        Ok(())
    }

    /// Vote for a user-defined event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) {
        self.vote_for_event(AccumulatingEvent::User(event));
    }

    /// Returns the set of peers that are responsible for collecting signatures to verify a message;
    /// this may contain us or only other nodes. If our signature is not required, this returns
    /// `None`.
    fn get_signature_targets(&self, src: &Authority<XorName>) -> Option<BTreeSet<XorName>> {
        let list: Vec<XorName> = match *src {
            Authority::Section(_) => self
                .chain
                .our_elders()
                .map(|p2p_node| p2p_node.name())
                .copied()
                .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs)),
            // FIXME: This does not include recently accepted peers which would affect quorum
            // calculation. This even when going via RT would have only allowed route-0 to succeed
            // as by ack-failure, the new node would have been accepted to the RT.
            // Need a better network startup separation.
            Authority::PrefixSection(pfx) => self
                .chain
                .all_sections()
                .flat_map(|(_, si)| si.member_names())
                .filter(|name| pfx.matches(name))
                .copied()
                .sorted_by(|lhs, rhs| src.name().cmp_distance(lhs, rhs)),
            Authority::Node(_) => {
                let mut result = BTreeSet::new();
                let _ = result.insert(*self.name());
                return Some(result);
            }
        };

        if !list.contains(&self.name()) {
            None
        } else {
            let len = list.len();
            Some(list.into_iter().take(delivery_group_size(len)).collect())
        }
    }

    /// Returns a list of target IDs for a message sent via route.
    /// Name in exclude will be excluded from the result.
    fn get_targets(
        &self,
        routing_msg: &RoutingMessage,
    ) -> Result<(Vec<PublicId>, usize), RoutingError> {
        // TODO: even if having chain reply based on connected_state,
        // we remove self in targets info and can do same by not
        // chaining us to conn_peer list here?
        let conn_peers = self.connected_peers();
        let (targets, dg_size) = self.chain.targets(&routing_msg.dst, &conn_peers)?;
        Ok((
            targets
                .into_iter()
                .filter_map(|name| self.peer_map.get_id(&name))
                .copied()
                .collect(),
            dg_size,
        ))
    }

    // TODO: Once `Chain::targets` uses the ideal state instead of the actually connected peers,
    // this should be removed.
    /// Returns all peers we are currently connected to, according to the peer manager, including
    /// ourselves.
    fn connected_peers(&self) -> Vec<&XorName> {
        self.peer_map
            .connected_ids()
            .map(|pub_id| pub_id.name())
            .chain(iter::once(self.name()))
            .collect()
    }

    // Check whether we are connected to any elders. If this node loses all elder connections,
    // it must be restarted.
    fn check_elder_connections(&mut self, outbox: &mut dyn EventBox) -> bool {
        if self
            .peer_map
            .connected_ids()
            .filter(|id| self.chain.our_id() != *id)
            .any(|id| self.chain.is_peer_our_elder(id))
        {
            true
        } else {
            debug!("{} - Lost all elder connections.", self);

            // Except network startup, restart in other cases.
            if *self.chain.our_info().version() > 0 {
                outbox.send_event(Event::RestartRequired);
                false
            } else {
                true
            }
        }
    }

    fn check_signed_message_trust(&self, msg: &SignedRoutingMessage) -> Result<(), RoutingError> {
        if msg.check_trust(&self.chain) {
            Ok(())
        } else {
            log_or_panic!(
                LogLevel::Error,
                "{} - Untrusted {:?} --- [{:?}]",
                self,
                msg,
                self.chain.get_their_keys_info().format(", ")
            );
            Err(RoutingError::UntrustedMessage)
        }
    }

    fn check_signed_relocation_details(&self, details: &SignedRelocateDetails) -> bool {
        if !self.chain.check_trust(&details.proof()) {
            log_or_panic!(LogLevel::Error, "{} - Untrusted {:?}", self, details);
            return false;
        }

        if !details.verify() {
            log_or_panic!(
                LogLevel::Error,
                "{} - Invalid signature of {:?}",
                self,
                details
            );
            return false;
        }

        true
    }

    fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain.our_prefix()
    }

    fn add_elder(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        let to_vote_infos = self.chain.add_elder(pub_id)?;

        self.send_event(Event::NodeAdded(*pub_id.name()), outbox);
        self.print_rt_size();

        for info in to_vote_infos {
            let participants: BTreeSet<_> = info.member_ids().copied().collect();
            let _ = self.dkg_cache.insert(participants.clone(), info);
            self.vote_for_event(AccumulatingEvent::StartDkg(participants));
        }

        Ok(())
    }

    fn remove_elder(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        let self_info = self.chain.remove_elder(pub_id)?;

        let participants: BTreeSet<_> = self_info.member_ids().copied().collect();
        let _ = self.dkg_cache.insert(participants.clone(), self_info);
        self.vote_for_event(AccumulatingEvent::StartDkg(participants));

        self.send_event(Event::NodeLost(*pub_id.name()), outbox);

        Ok(())
    }
}

impl Base for Elder {
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

    fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        let conn_peers = self.connected_peers();
        self.chain.closest_names(&name, count, &conn_peers)
    }

    fn dev_params(&self) -> &DevParams {
        self.chain.dev_params()
    }

    fn dev_params_mut(&mut self) -> &mut DevParams {
        self.chain.dev_params_mut()
    }

    fn peer_map(&self) -> &PeerMap {
        &self.peer_map
    }

    fn peer_map_mut(&mut self) -> &mut PeerMap {
        &mut self.peer_map
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn finish_handle_transition(&mut self, outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - State change to Elder finished.", self);

        // Complete the polling that was interupted by the transition.
        let _ = self.parsec_poll(outbox);

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

        if let Transition::Stay = &transition {
            for msg in mem::replace(&mut self.routing_msg_backlog, Default::default()) {
                if let Err(err) = self.handle_filtered_signed_message(msg) {
                    debug!("{} - {:?}", self, err);
                }
            }
        }

        transition
    }

    fn handle_send_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: Vec<u8>,
    ) -> Result<(), InterfaceError> {
        match self.send_user_message(src, dst, content) {
            Err(RoutingError::Interface(err)) => Err(err),
            Err(_) | Ok(()) => Ok(()),
        }
    }

    fn handle_timeout(&mut self, token: u64, outbox: &mut dyn EventBox) -> Transition {
        if self.tick_timer_token == token {
            // TODO: we no longer need tick for any internal purposes. Verify it is not needed by
            // the upper layers and remove it.
            self.tick_timer_token = self.timer.schedule(TICK_TIMEOUT);
            outbox.send_event(Event::TimerTicked);
        } else if self.gossip_timer_token == token {
            self.gossip_timer_token = self.timer.schedule(GOSSIP_TIMEOUT);

            // If we're the only node then invoke parsec_poll directly
            if self.chain.our_info().len() == 1 {
                let _ = self.parsec_poll(outbox);
            }

            self.send_parsec_gossip(None);
            self.maintain_parsec();
        }

        Transition::Stay
    }

    fn finish_handle_action(&mut self, outbox: &mut dyn EventBox) -> Transition {
        self.handle_routing_messages(outbox)
    }

    fn handle_bootstrapped_to(&mut self, conn_info: ConnectionInfo) -> Transition {
        // A mature node doesn't need a bootstrap connection
        self.network_service
            .service_mut()
            .disconnect_from(conn_info.peer_addr);
        Transition::Stay
    }

    fn handle_peer_lost(&mut self, pub_id: PublicId, outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - Lost peer {}", self, pub_id);

        if !self.check_elder_connections(outbox) {
            return Transition::Terminate;
        }

        if self.chain.is_peer_our_member(&pub_id) {
            self.vote_for_event(AccumulatingEvent::Offline(pub_id));
        }

        if self.chain.is_peer_elder(&pub_id) {
            debug!(
                "{} - Sending connection request to {} due to lost peer.",
                self, pub_id
            );

            let our_name = *self.name();
            let _ = self.send_connection_request(
                pub_id,
                Authority::Node(our_name),
                Authority::Node(*pub_id.name()),
                outbox,
            );
        }

        Transition::Stay
    }

    fn finish_handle_network_event(&mut self, outbox: &mut dyn EventBox) -> Transition {
        self.handle_routing_messages(outbox)
    }

    // Deconstruct a `DirectMessage` and handle or forward as appropriate.
    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        p2p_node: P2pNode,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let pub_id = *p2p_node.public_id();
        use crate::messages::DirectMessage::*;
        match msg {
            MessageSignature(msg) => self.handle_message_signature(msg, pub_id)?,
            BootstrapRequest(name) => {
                if let Err(error) = self.handle_bootstrap_request(pub_id, name) {
                    warn!(
                        "{} Invalid BootstrapRequest received from {} ({:?}).",
                        self, pub_id, error,
                    );
                }
            }
            ConnectionResponse => self.handle_connection_response(pub_id, outbox),
            JoinRequest(payload) => self.handle_join_request(p2p_node, payload),
            ParsecPoke(version) => self.handle_parsec_poke(version, pub_id),
            ParsecRequest(version, par_request) => {
                return self.handle_parsec_request(version, par_request, pub_id, outbox);
            }
            ParsecResponse(version, par_response) => {
                return self.handle_parsec_response(version, par_response, pub_id, outbox);
            }
            Relocate(details) => {
                return Ok(self.handle_relocate(details));
            }
            BootstrapResponse(_) => {
                debug!("{} Unhandled direct message: {:?}", self, msg);
            }
        }
        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let HopMessage { content, .. } = msg;
        self.handle_signed_message(content)
            .map(|()| Transition::Stay)
    }

    // Constructs a signed message, finds the nodes responsible for accumulation, and either sends
    // these nodes a signature or tries to accumulate signatures for this message (on success, the
    // accumulator handles or forwards the message).
    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        if !self.in_authority(&routing_msg.src) {
            log_or_panic!(
                LogLevel::Error,
                "{} Not part of the source authority. Not sending message {:?}.",
                self,
                routing_msg
            );
            return Ok(());
        }

        // If the source is single, we don't even need to send signatures, so let's cut this short
        if !routing_msg.src.is_multiple() {
            let mut msg = SignedRoutingMessage::single_source(routing_msg, &self.full_id)?;
            if self.in_authority(&msg.routing_message().dst) {
                self.handle_signed_message(msg)?;
            } else {
                self.send_signed_message(&mut msg)?;
            }
            return Ok(());
        }

        let proof = self.chain.prove(&routing_msg.dst);
        let pk_set = self.public_key_set();
        let signed_msg = SignedRoutingMessage::new(routing_msg, &self.full_id, pk_set, proof)?;

        for target in Iterator::flatten(
            self.get_signature_targets(&signed_msg.routing_message().src)
                .into_iter(),
        ) {
            if target == *self.name() {
                if let Some(mut msg) = self.sig_accumulator.add_proof(signed_msg.clone()) {
                    if self.in_authority(&msg.routing_message().dst) {
                        self.handle_signed_message(msg)?;
                    } else {
                        self.send_signed_message(&mut msg)?;
                    }
                }
            } else if let Some(&pub_id) = self.peer_map.get_id(&target) {
                trace!(
                    "{} Sending a signature for message {:?} to {:?}",
                    self,
                    signed_msg.routing_message(),
                    target
                );
                self.send_direct_message(
                    &pub_id,
                    DirectMessage::MessageSignature(signed_msg.clone()),
                );
            } else {
                error!(
                    "{} Failed to resolve signature target {:?} for message {:?}",
                    self,
                    target,
                    signed_msg.routing_message()
                );
            }
        }

        Ok(())
    }
}

#[cfg(feature = "mock_base")]
impl Elder {
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }

    pub fn has_unpolled_observations(&self) -> bool {
        if !self.chain.is_self_elder() {
            return false;
        }
        self.parsec_map.has_unpolled_observations()
    }

    pub fn is_peer_our_elder(&self, pub_id: &PublicId) -> bool {
        self.chain.is_peer_our_elder(pub_id)
    }

    pub fn identify_connection(&mut self, pub_id: PublicId, peer_addr: SocketAddr) {
        self.peer_map.identify(pub_id, peer_addr)
    }

    pub fn send_msg_to_targets(
        &mut self,
        dst_targets: &[PublicId],
        dg_size: usize,
        message: Message,
    ) {
        self.send_message_to_targets(dst_targets, dg_size, message)
    }
}

impl Approved for Elder {
    fn send_event(&mut self, event: Event, outbox: &mut dyn EventBox) {
        outbox.send_event(event);
    }

    fn parsec_map(&self) -> &ParsecMap {
        &self.parsec_map
    }

    fn parsec_map_mut(&mut self) -> &mut ParsecMap {
        &mut self.parsec_map
    }

    fn chain_mut(&mut self) -> &mut Chain {
        &mut self.chain
    }

    fn set_pfx_successfully_polled(&mut self, val: bool) {
        self.pfx_is_successfully_polled = val;
    }

    fn is_pfx_successfully_polled(&self) -> bool {
        self.pfx_is_successfully_polled
    }

    fn handle_online_event(
        &mut self,
        payload: OnlinePayload,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_add_member(payload.p2p_node.public_id()) {
            info!("{} - ignore Online: {:?}.", self, payload);
            return Ok(());
        }

        info!("{} - handle Online: {:?}.", self, payload);

        let pub_id = *payload.p2p_node.public_id();
        self.chain.add_member(payload.p2p_node.clone(), payload.age);
        self.chain.increment_age_counters(&pub_id);

        if let Some(relocate_details) = self.chain.poll_relocation() {
            self.vote_for_relocate(relocate_details)?;
        }

        self.handle_candidate_approval(payload.p2p_node, outbox);

        // TODO: vote for StartDkg and only when that gets consensused, vote for AddElder.
        self.add_elder(pub_id, outbox)
    }

    fn handle_offline_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_remove_member(&pub_id) {
            info!("{} - ignore Offline: {}.", self, pub_id);
            return Ok(());
        }

        info!("{} - handle Offline: {}.", self, pub_id);
        self.chain.increment_age_counters(&pub_id);
        self.chain.remove_member(&pub_id);

        if let Some(relocate_details) = self.chain.poll_relocation() {
            self.vote_for_relocate(relocate_details)?;
        }

        self.remove_elder(pub_id, outbox)?;
        self.disconnect(&pub_id);

        Ok(())
    }

    fn handle_dkg_result_event(
        &mut self,
        participants: &BTreeSet<PublicId>,
        _dkg_result: &DkgResultWrapper,
    ) -> Result<(), RoutingError> {
        if let Some(info) = self.dkg_cache.remove(participants) {
            info!("{} - handle DkgResult: {:?}", self, participants);
            self.vote_for_section_info(info)?;
        } else {
            log_or_panic!(
                LogLevel::Error,
                "{} DKG for an unexpected info {:?}.",
                self,
                participants
            );
        }
        Ok(())
    }

    fn handle_our_merge_event(&mut self) -> Result<(), RoutingError> {
        self.merge_if_necessary()
    }

    fn handle_neighbour_merge_event(&mut self) -> Result<(), RoutingError> {
        self.merge_if_necessary()
    }

    fn handle_section_info_event(
        &mut self,
        elders_info: EldersInfo,
        old_pfx: Prefix<XorName>,
        neighbour_change: EldersChange,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        info!("{} - handle SectionInfo: {:?}.", self, elders_info);

        let self_sec_update = elders_info.prefix().matches(self.name());

        // Poll the relocate queue before the parsec reset, so it is not blocked waiting for the
        // genesis event. Cast the actual votes only after the parsec reset however, so they already
        // go to the new instance.
        let relocate_details = if self_sec_update {
            self.chain.poll_relocation()
        } else {
            None
        };

        if elders_info.prefix().is_extension_of(&old_pfx) {
            self.finalise_prefix_change()?;
            self.send_event(Event::SectionSplit(*elders_info.prefix()), outbox);
            // After a section split, the normal `send_neighbour_infos` action for the neighbouring
            // section will be triggered here (and only here).  Meanwhile own section's sending
            // action will be triggered at the other place later on (`self_sec_update` is true).
            if !elders_info.prefix().matches(self.name()) {
                self.send_neighbour_infos();
            }
        } else if old_pfx.is_extension_of(elders_info.prefix()) {
            self.finalise_prefix_change()?;
            self.send_event(Event::SectionMerged(*elders_info.prefix()), outbox);
        } else if self_sec_update {
            self.reset_parsec()?;
        }

        self.update_neighbour_connections(neighbour_change, outbox);

        if self_sec_update {
            // Vote to update our self messages proof
            self.vote_send_section_info_ack(SendAckMessagePayload {
                ack_prefix: *elders_info.prefix(),
                ack_version: *elders_info.version(),
            });

            self.send_neighbour_infos();
        }

        if let Some(relocate_details) = relocate_details {
            self.vote_for_relocate(relocate_details)?;
        }

        let _ = self.merge_if_necessary();

        Ok(Transition::Stay)
    }

    fn handle_their_key_info_event(
        &mut self,
        key_info: SectionKeyInfo,
    ) -> Result<(), RoutingError> {
        self.vote_send_section_info_ack(SendAckMessagePayload {
            ack_prefix: *key_info.prefix(),
            ack_version: *key_info.version(),
        });
        Ok(())
    }

    fn handle_send_ack_message_event(
        &mut self,
        ack_payload: SendAckMessagePayload,
    ) -> Result<(), RoutingError> {
        let src = Authority::Section(self.our_prefix().name());
        let dst = Authority::Section(ack_payload.ack_prefix.name());
        let content = MessageContent::AckMessage {
            src_prefix: *self.our_prefix(),
            ack_version: ack_payload.ack_version,
        };

        self.send_routing_message(RoutingMessage { src, dst, content })
    }

    fn handle_relocate_event(
        &mut self,
        details: RelocateDetails,
        signature: BlsSignature,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        if !self.chain.can_remove_member(&details.pub_id) {
            info!("{} - ignore Relocate: {:?} - not a member", self, details);
            return Ok(());
        }

        info!("{} - handle Relocate: {:?}.", self, details);

        let pub_id = details.pub_id;

        // Do not send the message to ourselves.
        if pub_id != *self.id() {
            // We need proof that is valid for both the relocating node and the target section. To
            // construct such proof, we create one proof for the relocating node and one for the target
            // section and then take the longer of the two. This works because the longer proof is a
            // superset of the shorter one. We need to do this because in rare cases, the relocating
            // node might be lagging behind the target section in the knowledge of the source section.
            let proof = {
                let proof_for_source = self.chain.prove(&Authority::Node(*details.pub_id.name()));
                let proof_for_target = self.chain.prove(&Authority::Section(details.destination));

                if proof_for_source.blocks_len() > proof_for_target.blocks_len() {
                    proof_for_source
                } else {
                    proof_for_target
                }
            };

            if let Some(conn_info) = self.chain.get_member_connection_info(&pub_id).cloned() {
                let message =
                    DirectMessage::Relocate(SignedRelocateDetails::new(details, proof, signature));
                self.send_direct_message(&conn_info, message);
            }
        }

        self.chain.remove_member(&pub_id);
        self.remove_elder(pub_id, outbox)?;
        self.disconnect(&pub_id);

        Ok(())
    }
}

impl Display for Elder {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Elder({}({:b}))", self.name(), self.our_prefix())
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
