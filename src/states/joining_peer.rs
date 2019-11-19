// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    adult::{Adult, AdultDetails},
    bootstrapping_peer::{BootstrappingPeer, BootstrappingPeerDetails},
    common::Base,
};
use crate::{
    chain::{DevParams, GenesisPfxInfo, NetworkParams},
    error::{InterfaceError, RoutingError},
    id::{FullId, P2pNode},
    messages::{DirectMessage, HopMessage, MessageContent, RoutingMessage, SignedRoutingMessage},
    outbox::EventBox,
    peer_map::PeerMap,
    relocation::RelocatePayload,
    rng::MainRng,
    routing_message_filter::RoutingMessageFilter,
    routing_table::Authority,
    state_machine::{State, Transition},
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use std::{
    fmt::{self, Display, Formatter},
    time::Duration,
};

/// Time after which bootstrap is cancelled (and possibly retried).
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(180);

pub struct JoiningPeerDetails {
    pub network_service: NetworkService,
    pub full_id: FullId,
    pub network_cfg: NetworkParams,
    pub timer: Timer,
    pub rng: MainRng,
    pub p2p_nodes: Vec<P2pNode>,
    pub relocate_payload: Option<RelocatePayload>,
    pub dev_params: DevParams,
}

// State of a node after bootstrapping, while joining a section
pub struct JoiningPeer {
    network_service: NetworkService,
    routing_msg_filter: RoutingMessageFilter,
    routing_msg_backlog: Vec<SignedRoutingMessage>,
    direct_msg_backlog: Vec<(P2pNode, DirectMessage)>,
    full_id: FullId,
    timer: Timer,
    rng: MainRng,
    join_token: u64,
    p2p_nodes: Vec<P2pNode>,
    relocate_payload: Option<RelocatePayload>,
    network_cfg: NetworkParams,
    dev_params: DevParams,
}

impl JoiningPeer {
    pub fn new(details: JoiningPeerDetails) -> Self {
        let join_token = details.timer.schedule(JOIN_TIMEOUT);

        let mut joining_peer = Self {
            network_service: details.network_service,
            routing_msg_filter: RoutingMessageFilter::new(),
            routing_msg_backlog: vec![],
            direct_msg_backlog: vec![],
            full_id: details.full_id,
            timer: details.timer,
            rng: details.rng,
            join_token,
            p2p_nodes: details.p2p_nodes,
            relocate_payload: details.relocate_payload,
            network_cfg: details.network_cfg,
            dev_params: details.dev_params,
        };

        joining_peer.send_join_requests();
        joining_peer
    }

    pub fn into_adult(
        self,
        gen_pfx_info: GenesisPfxInfo,
        outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        let details = AdultDetails {
            network_service: self.network_service,
            event_backlog: vec![],
            full_id: self.full_id,
            gen_pfx_info,
            routing_msg_backlog: self.routing_msg_backlog,
            direct_msg_backlog: self.direct_msg_backlog,
            routing_msg_filter: self.routing_msg_filter,
            timer: self.timer,
            rng: self.rng,
            network_cfg: self.network_cfg,
            dev_params: self.dev_params,
        };
        Adult::from_joining_peer(details, outbox).map(State::Adult)
    }

    pub fn rebootstrap(mut self) -> Result<State, RoutingError> {
        let full_id = FullId::gen(&mut self.rng);

        Ok(State::BootstrappingPeer(BootstrappingPeer::new(
            BootstrappingPeerDetails {
                network_service: self.network_service,
                full_id,
                network_cfg: self.network_cfg,
                timer: self.timer,
                rng: self.rng,
                dev_params: self.dev_params,
            },
        )))
    }

    fn send_join_requests(&mut self) {
        for dst in self.p2p_nodes.clone() {
            info!("{} - Sending JoinRequest to {}", self, dst.public_id());
            self.send_direct_message(
                dst.connection_info(),
                DirectMessage::JoinRequest(self.relocate_payload.clone()),
            );
        }
    }

    fn dispatch_routing_message(
        &mut self,
        msg: SignedRoutingMessage,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let (msg, metadata) = msg.into_parts();

        match msg {
            RoutingMessage {
                content: MessageContent::NodeApproval(gen_info),
                src: Authority::PrefixSection(_),
                dst: Authority::Node { .. },
            } => Ok(self.handle_node_approval(gen_info)),
            RoutingMessage {
                content:
                    MessageContent::ConnectionRequest {
                        conn_info, pub_id, ..
                    },
                src: Authority::Node(_),
                dst: Authority::Node(_),
            } => {
                self.peer_map_mut().insert(pub_id, conn_info.clone());
                self.send_direct_message(&conn_info, DirectMessage::ConnectionResponse);
                Ok(Transition::Stay)
            }
            _ => {
                debug!(
                    "{} - Unhandled routing message, adding to backlog: {:?}",
                    self, msg
                );
                self.routing_msg_backlog
                    .push(SignedRoutingMessage::from_parts(msg, metadata));
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
        warn!("{} - Cannot handle SendMessage - not joined.", self);
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        if self.join_token == token {
            debug!("{} - Timeout when trying to join a section.", self);

            // TODO: if we are relocating, preserve the relocation details to rebootstrap to the
            // same target section.

            self.network_service_mut().remove_and_disconnect_all();

            return Transition::Rebootstrap;
        }

        Transition::Stay
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        p2p_node: P2pNode,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        match msg {
            DirectMessage::ConnectionResponse | DirectMessage::BootstrapResponse(_) => (),
            _ => {
                debug!(
                    "{} Unhandled direct message from {}, adding to backlog: {:?}",
                    self,
                    p2p_node.public_id(),
                    msg
                );
                self.direct_msg_backlog.push((p2p_node, msg));
            }
        }

        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        let HopMessage { content: msg, .. } = msg;

        if !self
            .routing_msg_filter
            .filter_incoming(msg.routing_message())
            .is_new()
        {
            trace!(
                "{} Known message: {:?} - not handling further",
                self,
                msg.routing_message()
            );
            return Ok(Transition::Stay);
        }

        if self.in_authority(&msg.routing_message().dst) {
            self.check_signed_message_integrity(&msg)?;
            self.dispatch_routing_message(msg, outbox)
        } else {
            self.routing_msg_backlog.push(msg);
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

    fn dev_params(&self) -> &DevParams {
        &self.dev_params
    }

    fn dev_params_mut(&mut self) -> &mut DevParams {
        &mut self.dev_params
    }
}

impl Display for JoiningPeer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "JoiningPeer({})", self.name())
    }
}
