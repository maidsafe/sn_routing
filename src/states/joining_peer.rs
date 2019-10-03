// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    adult::{Adult, AdultDetails},
    bootstrapping_peer::BootstrappingPeer,
    common::Base,
};
use crate::{
    chain::GenesisPfxInfo,
    error::{InterfaceError, RoutingError},
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, RoutingMessage},
    outbox::EventBox,
    peer_manager::{PeerManager, PeerState},
    peer_map::PeerMap,
    quic_p2p::NodeInfo,
    routing_message_filter::RoutingMessageFilter,
    routing_table::Authority,
    state_machine::{State, Transition},
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    time::Duration,
};

// Time (in seconds) after which bootstrap is cancelled (and possibly retried).
const JOIN_TIMEOUT: Duration = Duration::from_secs(120);

// State of a node after bootstrapping, while joining a section
pub struct JoiningPeer {
    network_service: NetworkService,
    routing_msg_filter: RoutingMessageFilter,
    msg_backlog: Vec<RoutingMessage>,
    full_id: FullId,
    min_section_size: usize,
    peer_map: PeerMap,
    timer: Timer,
    join_token: u64,
}

impl JoiningPeer {
    pub fn new(
        network_service: NetworkService,
        full_id: FullId,
        min_section_size: usize,
        timer: Timer,
        peer_map: PeerMap,
        node_infos: Vec<NodeInfo>,
    ) -> Self {
        let join_token = timer.schedule(JOIN_TIMEOUT);

        let mut joining_peer = Self {
            network_service,
            routing_msg_filter: RoutingMessageFilter::new(),
            msg_backlog: vec![],
            full_id,
            min_section_size,
            timer: timer,
            peer_map,
            join_token,
        };

        for node_info in node_infos {
            joining_peer.send_join_request(node_info);
        }
        joining_peer
    }

    pub fn into_adult(
        self,
        gen_pfx_info: GenesisPfxInfo,
        outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        let mut peer_mgr = PeerManager::new();

        // initialise known peers to PeerState::Connected in the PeerManager
        for pub_id in self.peer_map.connected_ids() {
            peer_mgr.insert_peer(*pub_id, PeerState::Connected);
        }

        let details = AdultDetails {
            network_service: self.network_service,
            event_backlog: vec![],
            full_id: self.full_id,
            gen_pfx_info,
            min_section_size: self.min_section_size,
            msg_backlog: self.msg_backlog,
            peer_map: self.peer_map,
            peer_mgr,
            routing_msg_filter: self.routing_msg_filter,
            timer: self.timer,
        };
        Adult::from_joining_peer(details, outbox).map(State::Adult)
    }

    pub fn into_bootstrapping(self) -> Result<State, RoutingError> {
        Ok(State::BootstrappingPeer(BootstrappingPeer::new(
            self.network_service,
            FullId::new(),
            self.min_section_size,
            self.timer,
        )))
    }

    fn send_join_request(&mut self, dst: NodeInfo) {
        info!("{} Sending JoinRequest to {:?}.", self, dst);

        let message = if let Ok(message) = self.to_signed_direct_message(DirectMessage::JoinRequest)
        {
            message
        } else {
            return;
        };

        let conn_infos = vec![dst];
        let dg_size = 1;
        self.send_message_to_initial_targets(conn_infos, dg_size, message);
    }

    fn dispatch_routing_message(
        &mut self,
        msg: RoutingMessage,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::messages::MessageContent::*;
        match msg {
            RoutingMessage {
                content: NodeApproval(gen_info),
                src: Authority::PrefixSection(_),
                dst: Authority::Node { .. },
            } => Ok(self.handle_node_approval(gen_info)),
            _ => {
                debug!(
                    "{} - Unhandled routing message, adding to backlog: {:?}",
                    self, msg
                );
                self.msg_backlog.push(msg);
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_node_approval(&mut self, gen_pfx_info: GenesisPfxInfo) -> Transition {
        info!(
            "{} - This node has been approved to join the network!",
            self
        );
        Transition::IntoAdult { gen_pfx_info }
    }

    #[cfg(feature = "mock_base")]
    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }
}

impl Base for JoiningPeer {
    fn network_service(&self) -> &NetworkService {
        &self.network_service
    }

    fn network_service_mut(&mut self) -> &mut NetworkService {
        &mut self.network_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn in_authority(&self, dst: &Authority<XorName>) -> bool {
        dst.is_single() && dst.name() == *self.full_id.public_id().name()
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

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn handle_send_message(
        &mut self,
        _: Authority<XorName>,
        _: Authority<XorName>,
        _: Vec<u8>,
    ) -> Result<(), InterfaceError> {
        warn!("{} - Cannot handle SendMessage - not joined.", self);
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        if self.join_token == token {
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

    fn handle_connection_failure(
        &mut self,
        peer_addr: SocketAddr,
        _: &mut dyn EventBox,
    ) -> Transition {
        let _ = self.peer_map_mut().disconnect(peer_addr);

        Transition::Stay
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        _pub_id: PublicId,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        debug!("{} Unhandled direct message: {:?}", self, msg);

        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let HopMessage { content, .. } = msg;

        if self
            .routing_msg_filter
            .filter_incoming(content.routing_message())
            .is_new()
            && self.in_authority(&content.routing_message().dst)
        {
            self.dispatch_routing_message(content.into_routing_message(), outbox)
        } else {
            Ok(Transition::Stay)
        }
    }
    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        warn!(
            "{} - Tried to send a routing message: {:?}",
            self, routing_msg
        );
        Ok(())
    }
}

impl Display for JoiningPeer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "JoiningPeer({})", self.name())
    }
}
