// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    bootstrapping_peer::BootstrappingPeer,
    common::{Approved, Base},
    elder::{Elder, ElderDetails},
};
use crate::{
    chain::{
        Chain, EldersChange, EldersInfo, GenesisPfxInfo, SectionKeyInfo, SendAckMessagePayload,
    },
    error::{BootstrapResponseError, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    messages::{
        BootstrapResponse, DirectMessage, HopMessage, RoutingMessage, SignedRoutingMessage,
    },
    outbox::EventBox,
    parsec::ParsecMap,
    peer_map::PeerMap,
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix},
    state_machine::{State, Transition},
    time::Duration,
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use itertools::Itertools;
use std::fmt::{self, Display, Formatter};

const POKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Time after which the node reinitiates the bootstrap if it is not added to the section.
pub const ADD_TIMEOUT: Duration = Duration::from_secs(120);

pub struct AdultDetails {
    pub network_service: NetworkService,
    pub event_backlog: Vec<Event>,
    pub full_id: FullId,
    pub gen_pfx_info: GenesisPfxInfo,
    pub min_section_size: usize,
    pub msg_backlog: Vec<RoutingMessage>,
    pub peer_map: PeerMap,
    pub routing_msg_filter: RoutingMessageFilter,
    pub timer: Timer,
}

pub struct Adult {
    chain: Chain,
    network_service: NetworkService,
    event_backlog: Vec<Event>,
    full_id: FullId,
    gen_pfx_info: GenesisPfxInfo,
    /// Routing messages addressed to us that we cannot handle until we are established.
    msg_backlog: Vec<RoutingMessage>,
    parsec_map: ParsecMap,
    peer_map: PeerMap,
    poke_timer_token: u64,
    add_timer_token: u64,
    routing_msg_filter: RoutingMessageFilter,
    timer: Timer,
}

impl Adult {
    pub fn from_joining_peer(
        details: AdultDetails,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let public_id = *details.full_id.public_id();
        let poke_timer_token = details.timer.schedule(POKE_TIMEOUT);
        let add_timer_token = details.timer.schedule(ADD_TIMEOUT);

        let parsec_map = ParsecMap::new(details.full_id.clone(), &details.gen_pfx_info);
        let chain = Chain::new(
            details.min_section_size,
            public_id,
            details.gen_pfx_info.clone(),
        );

        let mut node = Self {
            chain,
            network_service: details.network_service,
            event_backlog: details.event_backlog,
            full_id: details.full_id,
            gen_pfx_info: details.gen_pfx_info,
            msg_backlog: details.msg_backlog,
            parsec_map,
            peer_map: details.peer_map,
            routing_msg_filter: details.routing_msg_filter,
            timer: details.timer,
            poke_timer_token,
            add_timer_token,
        };

        node.init(outbox)?;
        Ok(node)
    }

    fn init(&mut self, outbox: &mut dyn EventBox) -> Result<(), RoutingError> {
        debug!("{} - State changed to Adult.", self);

        for msg in self.msg_backlog.drain(..).collect_vec() {
            self.dispatch_routing_message(msg, outbox)?;
        }

        Ok(())
    }

    pub fn into_bootstrapping(self) -> Result<State, RoutingError> {
        let min_section_size = self.min_section_size();
        Ok(State::BootstrappingPeer(BootstrappingPeer::new(
            self.network_service,
            FullId::new(),
            min_section_size,
            self.timer,
        )))
    }

    pub fn into_elder(
        self,
        elders_info: EldersInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        let details = ElderDetails {
            chain: self.chain,
            network_service: self.network_service,
            event_backlog: self.event_backlog,
            full_id: self.full_id,
            gen_pfx_info: self.gen_pfx_info,
            msg_queue: self.msg_backlog.into_iter().collect(),
            parsec_map: self.parsec_map,
            peer_map: self.peer_map,
            // we reset the message filter so that the node can correctly process some messages as
            // an Elder even if it has already seen them as an Adult
            routing_msg_filter: RoutingMessageFilter::new(),
            timer: self.timer,
        };

        Elder::from_adult(details, elders_info, old_pfx, outbox).map(State::Elder)
    }

    fn dispatch_routing_message(
        &mut self,
        msg: RoutingMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        use crate::{messages::MessageContent::*, routing_table::Authority::*};

        let src_name = msg.src.name();

        match msg {
            RoutingMessage {
                content:
                    ConnectionRequest {
                        conn_info,
                        pub_id,
                        msg_id,
                    },
                src: Node(_),
                dst: Node(_),
            } => {
                if self.chain.our_prefix().matches(&src_name) {
                    self.handle_connection_request(&conn_info, pub_id, msg.src, msg.dst, outbox)
                } else {
                    self.add_message_to_backlog(RoutingMessage {
                        content: ConnectionRequest {
                            conn_info,
                            pub_id,
                            msg_id,
                        },
                        ..msg
                    });
                    Ok(())
                }
            }
            _ => {
                self.add_message_to_backlog(msg);
                Ok(())
            }
        }
    }

    // Sends a `ParsecPoke` message to trigger a gossip request from current section members to us.
    //
    // TODO: Should restrict targets to few(counter churn-threshold)/single.
    // Currently this can result in incoming spam of gossip history from everyone.
    // Can also just be a single target once node-ageing makes Offline votes Opaque which should
    // remove invalid test failures for unaccumulated parsec::Remove blocks.
    fn send_parsec_poke(&mut self) {
        let version = *self.gen_pfx_info.first_info.version();
        let recipients = self
            .gen_pfx_info
            .latest_info
            .members()
            .iter()
            .filter(|pub_id| self.peer_map.has(pub_id))
            .copied()
            .collect_vec();

        for recipient in recipients {
            self.send_direct_message(&recipient, DirectMessage::ParsecPoke(version));
        }
    }

    // Backlog the message to be processed once we are established.
    fn add_message_to_backlog(&mut self, msg: RoutingMessage) {
        trace!(
            "{} Not established yet. Delaying message handling: {:?}",
            self,
            msg
        );
        self.msg_backlog.push(msg)
    }

    // Reject the bootstrap request, because only Elders can handle it.
    fn handle_bootstrap_request(&mut self, pub_id: PublicId) {
        debug!(
            "{} - Joining node {:?} rejected: We are not an established node yet.",
            self, pub_id
        );

        self.send_direct_message(
            &pub_id,
            DirectMessage::BootstrapResponse(BootstrapResponse::Error(
                BootstrapResponseError::NotApproved,
            )),
        );
        self.disconnect(&pub_id);
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

    fn min_section_size(&self) -> usize {
        self.chain.min_sec_size()
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

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        if self.poke_timer_token == token {
            self.send_parsec_poke();
            self.poke_timer_token = self.timer.schedule(POKE_TIMEOUT);
        } else if self.add_timer_token == token {
            debug!("{} - Timeout when trying to join a section.", self);

            for peer_addr in self
                .peer_map
                .remove_all()
                .map(|conn_info| conn_info.peer_addr)
            {
                self.network_service
                    .service_mut()
                    .disconnect_from(peer_addr);
            }

            return Transition::Rebootstrap;
        }

        Transition::Stay
    }

    fn handle_peer_lost(&mut self, pub_id: PublicId, _: &mut dyn EventBox) -> Transition {
        debug!("{} - Lost peer {}", self, pub_id);
        Transition::Stay
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::messages::DirectMessage::*;
        match msg {
            ParsecRequest(version, par_request) => {
                self.handle_parsec_request(version, par_request, pub_id, outbox)
            }
            ParsecResponse(version, par_response) => {
                self.handle_parsec_response(version, par_response, pub_id, outbox)
            }
            BootstrapRequest => {
                self.handle_bootstrap_request(pub_id);
                Ok(Transition::Stay)
            }
            _ => {
                debug!("{} Unhandled direct message: {:?}", self, msg);
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let HopMessage { content, .. } = msg;
        let routing_msg = content.into_routing_message();

        if self
            .routing_msg_filter
            .filter_incoming(&routing_msg)
            .is_new()
            && self.in_authority(&routing_msg.dst)
        {
            self.dispatch_routing_message(routing_msg, outbox)?;
        }

        Ok(Transition::Stay)
    }

    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        if self.in_authority(&routing_msg.dst) {
            return Ok(()); // Message is for us.
        }

        let signed_msg = SignedRoutingMessage::single_source(routing_msg, self.full_id())?;

        // We should only be connected to our own Elders - send to all of them
        // Need to collect IDs first so that self is not borrowed via the iterator
        let target_ids: Vec<_> = self.peer_map.connected_ids().cloned().collect();

        for pub_id in target_ids {
            if self
                .routing_msg_filter
                .filter_outgoing(signed_msg.routing_message(), &pub_id)
                .is_new()
            {
                let message = self.to_hop_message(signed_msg.clone())?;
                self.send_message(&pub_id, message);
            }
        }

        Ok(())
    }
}

impl Approved for Adult {
    fn send_event(&mut self, event: Event, _: &mut dyn EventBox) {
        self.event_backlog.push(event)
    }

    fn parsec_map_mut(&mut self) -> &mut ParsecMap {
        &mut self.parsec_map
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

    fn handle_add_elder_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        info!("{} - Added elder {}.", self, pub_id);
        let _ = self.chain.add_elder(pub_id)?;
        self.send_event(Event::NodeAdded(*pub_id.name()), outbox);

        // As Adult, we only connect to the elders in our section.
        self.send_connection_request(
            pub_id,
            Authority::Node(*self.name()),
            Authority::Node(*pub_id.name()),
            outbox,
        )
    }

    fn handle_remove_elder_event(
        &mut self,
        pub_id: PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        info!("{} - Removed elder {}.", self, pub_id);
        let _ = self.chain.remove_elder(pub_id)?;
        self.disconnect(&pub_id);
        self.send_event(Event::NodeLost(*pub_id.name()), outbox);

        Ok(())
    }

    fn handle_online_event(
        &mut self,
        pub_id: PublicId,
        _: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
        self.chain.add_member(pub_id);
        Ok(())
    }

    fn handle_offline_event(&mut self, pub_id: PublicId) -> Result<(), RoutingError> {
        self.chain.remove_member(&pub_id);
        Ok(())
    }

    fn handle_section_info_event(
        &mut self,
        elders_info: EldersInfo,
        old_pfx: Prefix<XorName>,
        _neighbour_change: EldersChange,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        if self.chain.is_self_elder() {
            Ok(Transition::IntoElder {
                elders_info,
                old_pfx,
            })
        } else {
            debug!("{} - Unhandled SectionInfo event", self);
            Ok(Transition::Stay)
        }
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

    fn handle_our_merge_event(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled OurMerge event", self);
        Ok(())
    }

    fn handle_neighbour_merge_event(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled NeighbourMerge event", self);
        Ok(())
    }
}

impl Display for Adult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Adult({}({:b}))",
            self.name(),
            self.chain.our_prefix()
        )
    }
}
