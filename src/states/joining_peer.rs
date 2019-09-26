// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    adult::{Adult, AdultDetails},
    common::{Base, Bootstrapped, BootstrappedNotEstablished},
};
use crate::{
    chain::GenesisPfxInfo,
    error::{InterfaceError, RoutingError},
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, RoutingMessage},
    outbox::EventBox,
    peer_manager::{PeerManager, PeerState},
    peer_map::PeerMap,
    quic_p2p::{NodeInfo, Peer},
    routing_message_filter::RoutingMessageFilter,
    routing_table::Authority,
    state_machine::{State, Transition},
    time::Instant,
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

// State of a node after bootstrapping, while joining a section
pub struct JoiningPeer {
    network_service: NetworkService,
    routing_msg_filter: RoutingMessageFilter,
    full_id: FullId,
    min_section_size: usize,
    peer_map: PeerMap,
    timer: Timer,
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
        let mut joining_peer = Self {
            network_service,
            routing_msg_filter: RoutingMessageFilter::new(),
            full_id,
            min_section_size,
            timer: timer,
            peer_map,
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
            msg_backlog: vec![],
            peer_map: self.peer_map,
            peer_mgr,
            routing_msg_filter: self.routing_msg_filter,
            timer: self.timer,
        };
        Adult::from_joining_peer(details, outbox).map(State::Adult)
    }

    fn send_join_request(&mut self, dst: NodeInfo) {
        info!("{} Sending JoinRequest to {:?}.", self, dst);

        let message = if let Ok(message) = self.to_signed_direct_message(DirectMessage::JoinRequest)
        {
            message
        } else {
            return;
        };

        let conn_infos = vec![Peer::Node { node_info: dst }];

        let dg_size = 1;
        self.send_message_to_initial_targets(conn_infos, dg_size, message);
    }

    fn dispatch_routing_message(
        &mut self,
        msg: RoutingMessage,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::{messages::MessageContent::*, routing_table::Authority::*};
        match msg {
            RoutingMessage {
                content: NodeApproval(gen_info),
                src: PrefixSection(_),
                dst: ManagedNode { .. },
            } => Ok(self.handle_node_approval(gen_info)),
            _ => {
                debug!("{} - Unhandled routing message: {:?}", self, msg);
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
        if let Some(routing_msg) = self.filter_hop_message(msg)? {
            self.dispatch_routing_message(routing_msg, outbox)
        } else {
            Ok(Transition::Stay)
        }
    }
}

impl Bootstrapped for JoiningPeer {
    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn send_routing_message_impl(
        &mut self,
        routing_msg: RoutingMessage,
        _expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        warn!(
            "{} - Tried to send a routing message: {:?}",
            self, routing_msg
        );
        Ok(())
    }
}

impl BootstrappedNotEstablished for JoiningPeer {
    fn get_proxy_public_id(&self, _proxy_name: &XorName) -> Result<&PublicId, RoutingError> {
        Err(RoutingError::InvalidPeer)
    }
}

impl Display for JoiningPeer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "JoiningPeer({})", self.name())
    }
}
