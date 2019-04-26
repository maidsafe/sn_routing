// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    common::{
        proxied, Approved, Base, Bootstrapped, NotEstablished, Relocated, RelocatedNotEstablished,
    },
    node::Node,
};
use crate::{
    ack_manager::AckManager,
    cache::Cache,
    chain::{Chain, ExpectCandidatePayload, GenesisPfxInfo, ProvingSection, SectionInfo},
    error::RoutingError,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, Message, RoutingMessage},
    outbox::EventBox,
    parsec::ParsecMap,
    peer_manager::{Peer, PeerManager, PeerState},
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix},
    state_machine::{State, Transition},
    time::{Duration, Instant},
    timer::Timer,
    xor_name::XorName,
    Service,
};
use itertools::Itertools;
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};

const POKE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct EstablishingNode {
    ack_mgr: AckManager,
    cache: Box<Cache>,
    chain: Chain,
    crust_service: Service,
    full_id: FullId,
    gen_pfx_info: GenesisPfxInfo,
    /// Routing messages addressed to us that we cannot handle until we are established.
    msg_backlog: Vec<RoutingMessage>,
    notified_nodes: BTreeSet<PublicId>,
    parsec_map: ParsecMap,
    peer_mgr: PeerManager,
    poke_timer_token: u64,
    routing_msg_filter: RoutingMessageFilter,
    timer: Timer,
}

impl EstablishingNode {
    #[allow(clippy::too_many_arguments)]
    pub fn from_proving_node(
        ack_mgr: AckManager,
        cache: Box<Cache>,
        crust_service: Service,
        full_id: FullId,
        gen_pfx_info: GenesisPfxInfo,
        min_section_size: usize,
        msg_backlog: Vec<RoutingMessage>,
        notified_nodes: BTreeSet<PublicId>,
        peer_mgr: PeerManager,
        routing_msg_filter: RoutingMessageFilter,
        timer: Timer,
        outbox: &mut EventBox,
    ) -> Result<Self, RoutingError> {
        let public_id = *full_id.public_id();
        let poke_timer_token = timer.schedule(POKE_TIMEOUT);

        let parsec_map = ParsecMap::new(full_id.clone(), &gen_pfx_info);
        let chain = Chain::new(min_section_size, public_id, gen_pfx_info.clone());

        let mut node = Self {
            ack_mgr,
            cache,
            chain,
            crust_service,
            full_id,
            gen_pfx_info,
            msg_backlog: vec![],
            notified_nodes,
            parsec_map,
            peer_mgr,
            poke_timer_token,
            routing_msg_filter,
            timer,
        };

        node.init(msg_backlog, outbox)?;
        Ok(node)
    }

    fn init(
        &mut self,
        msg_backlog: Vec<RoutingMessage>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        debug!("{} - State changed to EstablishingNode.", self);

        for msg in msg_backlog {
            let _ = self.dispatch_routing_message(msg, outbox)?;
        }

        Ok(())
    }

    pub fn into_node(
        self,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        outbox: &mut EventBox,
    ) -> State {
        let node = Node::from_establishing_node(
            self.ack_mgr,
            self.cache,
            self.chain,
            self.crust_service,
            self.full_id,
            self.gen_pfx_info,
            self.msg_backlog.into_iter().collect(),
            self.notified_nodes,
            old_pfx,
            self.parsec_map,
            self.peer_mgr,
            self.routing_msg_filter,
            sec_info,
            self.timer,
            outbox,
        );

        match node {
            Ok(node) => State::Node(node),
            Err(_) => State::Terminated,
        }
    }

    fn dispatch_routing_message(
        &mut self,
        msg: RoutingMessage,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        self.handle_routing_message(msg, outbox)
            .map(|()| Transition::Stay)
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
            .cloned()
            .collect_vec();

        for recipient in recipients {
            self.send_message(
                &recipient,
                Message::Direct(DirectMessage::ParsecPoke(version)),
            );
        }
    }
}

#[cfg(feature = "mock_base")]
impl EstablishingNode {
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }

    pub fn has_unpolled_observations(&self, filter_opaque: bool) -> bool {
        self.parsec_map.has_unpolled_observations(filter_opaque)
    }
}

impl Base for EstablishingNode {
    fn crust_service(&self) -> &Service {
        &self.crust_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn in_authority(&self, auth: &Authority<XorName>) -> bool {
        if let Authority::Client { ref client_id, .. } = *auth {
            client_id == self.full_id.public_id()
        } else {
            false
        }
    }

    fn min_section_size(&self) -> usize {
        self.chain.min_sec_size()
    }

    fn handle_timeout(&mut self, token: u64, _: &mut EventBox) -> Transition {
        if self.poke_timer_token == token {
            self.send_parsec_poke();
            self.poke_timer_token = self.timer.schedule(POKE_TIMEOUT);
        } else {
            self.resend_unacknowledged_timed_out_msgs(token);
        }

        Transition::Stay
    }

    fn handle_connect_success(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        Relocated::handle_connect_success(self, pub_id, outbox)
    }

    fn handle_connect_failure(&mut self, pub_id: PublicId, _: &mut EventBox) -> Transition {
        RelocatedNotEstablished::handle_connect_failure(self, pub_id)
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        self.check_direct_message_sender(&msg, &pub_id)?;

        use crate::messages::DirectMessage::*;
        match msg {
            ParsecRequest(version, par_request) => {
                self.handle_parsec_request(version, par_request, pub_id, outbox)
            }
            ParsecResponse(version, par_response) => {
                self.handle_parsec_response(version, par_response, pub_id, outbox)
            }
            BootstrapRequest(_) => {
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
        hop_msg: HopMessage,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        match self.peer_mgr.get_peer(&pub_id).map(Peer::state) {
            Some(&PeerState::Connected) | Some(&PeerState::Proxy) => (),
            _ => return Err(RoutingError::UnknownConnection(pub_id)),
        }

        if let Some(routing_msg) = self.filter_hop_message(hop_msg, pub_id)? {
            self.dispatch_routing_message(routing_msg, outbox)
        } else {
            Ok(Transition::Stay)
        }
    }
}

impl Bootstrapped for EstablishingNode {
    fn ack_mgr(&self) -> &AckManager {
        &self.ack_mgr
    }

    fn ack_mgr_mut(&mut self) -> &mut AckManager {
        &mut self.ack_mgr
    }

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn send_routing_message_via_route(
        &mut self,
        routing_msg: RoutingMessage,
        src_section: Option<SectionInfo>,
        route: u8,
        expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message_via_proxy(routing_msg, src_section, route, expires_at)
    }
}

impl Relocated for EstablishingNode {
    fn peer_mgr(&self) -> &PeerManager {
        &self.peer_mgr
    }

    fn peer_mgr_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_mgr
    }

    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        if self.chain.is_peer_valid(&pub_id) {
            self.add_to_routing_table(&pub_id, outbox);
        }
    }

    fn is_peer_valid(&self, _pub_id: &PublicId) -> bool {
        true
    }

    fn add_to_notified_nodes(&mut self, pub_id: PublicId) -> bool {
        self.notified_nodes.insert(pub_id)
    }

    fn remove_from_notified_nodes(&mut self, pub_id: &PublicId) -> bool {
        self.notified_nodes.remove(pub_id)
    }

    fn add_to_routing_table_success(&mut self, _: &PublicId) {}

    fn add_to_routing_table_failure(&mut self, pub_id: &PublicId) {
        self.disconnect_peer(pub_id)
    }
}

impl NotEstablished for EstablishingNode {
    const SEND_ACK: bool = true;

    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId, RoutingError> {
        proxied::find_proxy_public_id(self, &self.peer_mgr, proxy_name)
    }
}

impl RelocatedNotEstablished for EstablishingNode {
    fn our_prefix(&self) -> &Prefix<XorName> {
        self.chain.our_prefix()
    }

    fn push_message_to_backlog(&mut self, msg: RoutingMessage) {
        self.msg_backlog.push(msg)
    }
}

impl Approved for EstablishingNode {
    fn parsec_map_mut(&mut self) -> &mut ParsecMap {
        &mut self.parsec_map
    }

    fn chain_mut(&mut self) -> &mut Chain {
        &mut self.chain
    }

    fn handle_online_event(
        &mut self,
        new_pub_id: PublicId,
        _: Authority<XorName>,
        _: &mut EventBox,
    ) -> Result<(), RoutingError> {
        let _ = self.chain.add_member(new_pub_id)?;
        Ok(())
    }

    fn handle_offline_event(
        &mut self,
        pub_id: PublicId,
        _: &mut EventBox,
    ) -> Result<(), RoutingError> {
        let _ = self.chain.remove_member(pub_id)?;
        Ok(())
    }

    fn handle_expect_candidate_event(
        &mut self,
        _: ExpectCandidatePayload,
    ) -> Result<(), RoutingError> {
        Ok(())
    }

    fn handle_section_info_event(
        &mut self,
        sec_info: SectionInfo,
        old_pfx: Prefix<XorName>,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        if self.chain.is_member() {
            Ok(Transition::IntoNode { sec_info, old_pfx })
        } else {
            debug!("{} - Unhandled SectionInfo event", self);
            Ok(Transition::Stay)
        }
    }

    fn handle_our_merge_event(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled OurMerge event", self);
        Ok(())
    }

    fn handle_neighbour_merge_event(&mut self) -> Result<(), RoutingError> {
        debug!("{} - Unhandled NeighbourMerge event", self);
        Ok(())
    }

    fn handle_proving_sections_event(
        &mut self,
        _: Vec<ProvingSection>,
        _: SectionInfo,
    ) -> Result<(), RoutingError> {
        debug!("{} - Unhandled ProvingSections event", self);
        Ok(())
    }
}

impl Display for EstablishingNode {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "EstablishingNode({}({:b}))",
            self.name(),
            self.chain.our_prefix()
        )
    }
}
