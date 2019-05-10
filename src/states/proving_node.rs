// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    common::{
        proxied, Base, Bootstrapped, BootstrappedNotEstablished, Relocated, RelocatedNotEstablished,
    },
    establishing_node::{EstablishingNode, EstablishingNodeDetails},
};
use crate::{
    ack_manager::AckManager,
    cache::Cache,
    chain::{GenesisPfxInfo, SectionInfo},
    config_handler,
    crust::{CrustError, PrivConnectionInfo},
    error::RoutingError,
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, RoutingMessage},
    outbox::EventBox,
    peer_manager::{Peer, PeerManager, PeerState},
    resource_prover::ResourceProver,
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix},
    state_machine::State,
    state_machine::Transition,
    time::Instant,
    timer::Timer,
    types::RoutingActionSender,
    xor_name::XorName,
    Service,
};
use maidsafe_utilities::serialisation;
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};

pub struct ProvingNodeDetails {
    pub action_sender: RoutingActionSender,
    pub cache: Box<Cache>,
    pub crust_service: Service,
    pub full_id: FullId,
    pub min_section_size: usize,
    pub old_full_id: FullId,
    pub our_section: (Prefix<XorName>, BTreeSet<PublicId>),
    pub proxy_pub_id: PublicId,
    pub timer: Timer,
}

pub struct ProvingNode {
    ack_mgr: AckManager,
    cache: Box<Cache>,
    crust_service: Service,
    /// Whether resource proof is disabled.
    disable_resource_proof: bool,
    event_backlog: Vec<Event>,
    full_id: FullId,
    joining_prefix: Prefix<XorName>,
    min_section_size: usize,
    /// Routing messages addressed to us that we cannot handle until we are approved.
    msg_backlog: Vec<RoutingMessage>,
    /// ID from before relocating.
    old_full_id: FullId,
    peer_mgr: PeerManager,
    resource_prover: ResourceProver,
    routing_msg_filter: RoutingMessageFilter,
    timer: Timer,
}

impl ProvingNode {
    pub fn from_bootstrapping(details: ProvingNodeDetails, outbox: &mut EventBox) -> Self {
        let dev_config = config_handler::get_config().dev.unwrap_or_default();
        let public_id = *details.full_id.public_id();

        let mut peer_mgr = PeerManager::new(public_id, dev_config.disable_client_rate_limiter);
        peer_mgr.insert_peer(Peer::new(details.proxy_pub_id, PeerState::Proxy));

        let challenger_count = details.our_section.1.len();
        let resource_prover = ResourceProver::new(
            details.action_sender,
            details.timer.clone(),
            challenger_count,
        );

        let mut node = Self {
            ack_mgr: AckManager::new(),
            cache: details.cache,
            crust_service: details.crust_service,
            event_backlog: Vec::new(),
            full_id: details.full_id,
            min_section_size: details.min_section_size,
            msg_backlog: Vec::new(),
            peer_mgr,
            routing_msg_filter: RoutingMessageFilter::new(),
            timer: details.timer,
            disable_resource_proof: dev_config.disable_resource_proof,
            joining_prefix: details.our_section.0,
            old_full_id: details.old_full_id,
            resource_prover,
        };
        node.init(details.our_section.1, &details.proxy_pub_id, outbox);
        node
    }

    /// Called immediately after construction. Sends `ConnectionInfoRequest`s to all members of
    /// `our_section` to then start the candidate approval process.
    fn init(
        &mut self,
        our_section: BTreeSet<PublicId>,
        proxy_pub_id: &PublicId,
        outbox: &mut EventBox,
    ) {
        self.resource_prover.start(self.disable_resource_proof);

        trace!("{} Relocation completed.", self);
        info!(
            "{} Received relocation section. Establishing connections to {} peers.",
            self,
            our_section.len()
        );

        let src = Authority::Client {
            client_id: *self.full_id.public_id(),
            proxy_node_name: *proxy_pub_id.name(),
        };

        for pub_id in &our_section {
            debug!(
                "{} Sending connection info request to {:?} on Relocation response.",
                self, pub_id
            );
            let dst = Authority::ManagedNode(*pub_id.name());
            if let Err(error) = self.send_connection_info_request(*pub_id, src, dst, outbox) {
                debug!(
                    "{} - Failed to send connection info request to {:?}: {:?}",
                    self, pub_id, error
                );
            }
        }
    }

    pub fn into_establishing_node(
        self,
        gen_pfx_info: GenesisPfxInfo,
        outbox: &mut EventBox,
    ) -> Result<State, RoutingError> {
        let details = EstablishingNodeDetails {
            ack_mgr: self.ack_mgr,
            cache: self.cache,
            crust_service: self.crust_service,
            event_backlog: self.event_backlog,
            full_id: self.full_id,
            gen_pfx_info,
            min_section_size: self.min_section_size,
            msg_backlog: self.msg_backlog,
            peer_mgr: self.peer_mgr,
            routing_msg_filter: self.routing_msg_filter,
            timer: self.timer,
        };

        EstablishingNode::from_proving_node(details, outbox).map(State::EstablishingNode)
    }

    fn dispatch_routing_message(
        &mut self,
        msg: RoutingMessage,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::{messages::MessageContent::*, routing_table::Authority::*};
        match msg {
            RoutingMessage {
                content: NodeApproval(gen_info),
                src: PrefixSection(_),
                dst: Client { .. },
            } => Ok(self.handle_node_approval(gen_info)),
            _ => self
                .handle_routing_message(msg, outbox)
                .map(|()| Transition::Stay),
        }
    }

    fn handle_node_approval(&mut self, gen_pfx_info: GenesisPfxInfo) -> Transition {
        self.resource_prover.handle_approval();
        info!(
            "{} Resource proof challenges completed. This node has been approved to join the \
             network!",
            self
        );

        Transition::IntoEstablishingNode { gen_pfx_info }
    }

    #[cfg(feature = "mock_base")]
    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }
}

impl Base for ProvingNode {
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
        self.min_section_size
    }

    fn handle_timeout(&mut self, token: u64, outbox: &mut EventBox) -> Transition {
        let log_ident = self.log_ident();
        if let Some(transition) = self
            .resource_prover
            .handle_timeout(token, log_ident, outbox)
        {
            transition
        } else {
            self.resend_unacknowledged_timed_out_msgs(token);
            Transition::Stay
        }
    }

    fn handle_resource_proof_result(&mut self, pub_id: PublicId, messages: Vec<DirectMessage>) {
        let msg = self
            .resource_prover
            .handle_action_res_proof(pub_id, messages);
        self.send_direct_message(pub_id, msg);
    }

    fn handle_connect_success(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        Relocated::handle_connect_success(self, pub_id, outbox)
    }

    fn handle_connect_failure(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        RelocatedNotEstablished::handle_connect_failure(self, pub_id, outbox)
    }

    fn handle_lost_peer(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        debug!("{} Received LostPeer - {}", self, pub_id);

        if self.dropped_peer(&pub_id, outbox) {
            Transition::Stay
        } else {
            outbox.send_event(Event::Terminated);
            Transition::Terminate
        }
    }

    fn handle_connection_info_prepared(
        &mut self,
        result_token: u32,
        result: Result<PrivConnectionInfo<PublicId>, CrustError>,
    ) -> Transition {
        Relocated::handle_connection_info_prepared(self, result_token, result)
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        _outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        self.check_direct_message_sender(&msg, &pub_id)?;

        use crate::messages::DirectMessage::*;
        match msg {
            ResourceProof {
                seed,
                target_size,
                difficulty,
            } => {
                let log_ident = self.log_ident();
                self.resource_prover.handle_request(
                    pub_id,
                    seed,
                    target_size,
                    difficulty,
                    log_ident,
                );
            }
            ResourceProofResponseReceipt => {
                if let Some(msg) = self.resource_prover.handle_receipt(pub_id) {
                    self.send_direct_message(pub_id, msg);
                }
            }
            BootstrapRequest(_) => self.handle_bootstrap_request(pub_id),
            _ => {
                debug!("{} Unhandled direct message: {:?}", self, msg);
            }
        }

        Ok(Transition::Stay)
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

impl Bootstrapped for ProvingNode {
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

impl Relocated for ProvingNode {
    fn peer_mgr(&self) -> &PeerManager {
        &self.peer_mgr
    }

    fn peer_mgr_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_mgr
    }

    fn process_connection(&mut self, pub_id: PublicId, _outbox: &mut EventBox) {
        // We're not approved yet - we need to identify ourselves with our old and new IDs via
        // `CandidateInfo`. Serialise the old and new `PublicId`s and sign this using the old key.
        let msg = {
            let old_and_new_pub_ids = (self.old_full_id.public_id(), self.full_id.public_id());
            let mut to_sign = match serialisation::serialise(&old_and_new_pub_ids) {
                Ok(result) => result,
                Err(error) => {
                    error!("Failed to serialise public IDs: {:?}", error);
                    return;
                }
            };
            let signature_using_old = self
                .old_full_id
                .signing_private_key()
                .sign_detached(&to_sign);
            // Append this signature onto the serialised IDs and sign that using the new key.
            to_sign.extend_from_slice(&signature_using_old.into_bytes());
            let signature_using_new = self.full_id.signing_private_key().sign_detached(&to_sign);
            let proxy_node_name = if let Some(proxy_node_name) = self.peer_mgr.get_proxy_name() {
                *proxy_node_name
            } else {
                warn!("{} No proxy found, so unable to send CandidateInfo.", self);
                return;
            };
            let new_client_auth = Authority::Client {
                client_id: *self.full_id.public_id(),
                proxy_node_name: proxy_node_name,
            };

            DirectMessage::CandidateInfo {
                old_public_id: *self.old_full_id.public_id(),
                new_public_id: *self.full_id.public_id(),
                signature_using_old: signature_using_old,
                signature_using_new: signature_using_new,
                new_client_auth: new_client_auth,
            }
        };

        self.send_direct_message(pub_id, msg);
    }

    fn is_peer_valid(&self, _: &PublicId) -> bool {
        true
    }

    fn add_node_success(&mut self, _: &PublicId) {}

    fn add_node_failure(&mut self, pub_id: &PublicId) {
        self.disconnect_peer(pub_id)
    }

    fn send_event(&mut self, event: Event, _: &mut EventBox) {
        self.event_backlog.push(event)
    }
}

impl BootstrappedNotEstablished for ProvingNode {
    const SEND_ACK: bool = true;

    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId, RoutingError> {
        proxied::find_proxy_public_id(self, &self.peer_mgr, proxy_name)
    }
}

impl RelocatedNotEstablished for ProvingNode {
    fn our_prefix(&self) -> &Prefix<XorName> {
        &self.joining_prefix
    }

    fn push_message_to_backlog(&mut self, msg: RoutingMessage) {
        self.msg_backlog.push(msg)
    }
}

impl Display for ProvingNode {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "ProvingNode({}({:b}))",
            self.name(),
            self.our_prefix()
        )
    }
}
