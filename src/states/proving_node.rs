// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    adult::{Adult, AdultDetails},
    common::{
        proxied, Base, Bootstrapped, BootstrappedNotEstablished, Relocated, RelocatedNotEstablished,
    },
};
use crate::{
    action::Action,
    chain::GenesisPfxInfo,
    config_handler,
    error::RoutingError,
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, RoutingMessage},
    outbox::EventBox,
    peer_manager::{PeerManager, PeerState},
    peer_map::PeerMap,
    resource_prover::ResourceProver,
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix},
    state_machine::State,
    state_machine::Transition,
    time::Instant,
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use crossbeam_channel as mpmc;
use maidsafe_utilities::serialisation;
use std::collections::btree_map::BTreeMap;
use std::time::Duration;
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};

const RESEND_TIMEOUT: Duration = Duration::from_secs(20);

pub struct ProvingNodeDetails {
    pub action_sender: mpmc::Sender<Action>,
    pub network_service: NetworkService,
    pub full_id: FullId,
    pub min_section_size: usize,
    pub old_full_id: FullId,
    pub our_section: (Prefix<XorName>, BTreeSet<PublicId>),
    pub peer_map: PeerMap,
    pub proxy_pub_id: PublicId,
    pub timer: Timer,
}

pub struct ProvingNode {
    network_service: NetworkService,
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
    peer_map: PeerMap,
    peer_mgr: PeerManager,
    resource_prover: ResourceProver,
    routing_msg_filter: RoutingMessageFilter,
    timer: Timer,
    resource_proofing_status: BTreeMap<PublicId, bool>,
    resend_token: Option<u64>,
}

impl ProvingNode {
    pub fn from_bootstrapping(
        details: ProvingNodeDetails,
        outbox: &mut dyn EventBox,
    ) -> Result<Self, RoutingError> {
        let dev_config = config_handler::get_config().dev.unwrap_or_default();

        let mut peer_mgr = PeerManager::new(dev_config.disable_client_rate_limiter);
        peer_mgr.insert_peer(details.proxy_pub_id, PeerState::Proxy);

        let challenger_count = details.our_section.1.len();
        let resource_prover = ResourceProver::new(
            details.action_sender,
            details.timer.clone(),
            challenger_count,
        );

        let mut node = Self {
            network_service: details.network_service,
            event_backlog: Vec::new(),
            full_id: details.full_id,
            min_section_size: details.min_section_size,
            msg_backlog: Vec::new(),
            peer_map: details.peer_map,
            peer_mgr,
            routing_msg_filter: RoutingMessageFilter::new(),
            timer: details.timer,
            disable_resource_proof: dev_config.disable_resource_proof,
            joining_prefix: details.our_section.0,
            old_full_id: details.old_full_id,
            resource_prover,
            resource_proofing_status: BTreeMap::new(),
            resend_token: None,
        };
        node.init(details.our_section.1, &details.proxy_pub_id, outbox)?;
        Ok(node)
    }

    /// Called immediately after construction. Sends `ConnectionInfoRequest`s to all members of
    /// `our_section` to then start the candidate approval process.
    fn init(
        &mut self,
        our_section: BTreeSet<PublicId>,
        proxy_pub_id: &PublicId,
        outbox: &mut dyn EventBox,
    ) -> Result<(), RoutingError> {
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

        for pub_id in our_section {
            debug!(
                "{} Sending ConnectionRequest to {:?} on Relocation response.",
                self, pub_id
            );

            let dst = Authority::ManagedNode(*pub_id.name());
            self.send_connection_request(pub_id, src, dst, outbox)?;
        }
        self.resend_token = Some(self.timer.schedule(RESEND_TIMEOUT));
        Ok(())
    }

    pub fn into_adult(
        self,
        gen_pfx_info: GenesisPfxInfo,
        outbox: &mut dyn EventBox,
    ) -> Result<State, RoutingError> {
        let details = AdultDetails {
            network_service: self.network_service,
            event_backlog: self.event_backlog,
            full_id: self.full_id,
            gen_pfx_info,
            min_section_size: self.min_section_size,
            msg_backlog: self.msg_backlog,
            peer_map: self.peer_map,
            peer_mgr: self.peer_mgr,
            routing_msg_filter: self.routing_msg_filter,
            timer: self.timer,
        };

        Adult::from_proving_node(details, outbox).map(State::Adult)
    }

    fn dispatch_routing_message(
        &mut self,
        msg: RoutingMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::{messages::MessageContent::*, routing_table::Authority::*};
        match msg {
            RoutingMessage {
                content: NodeApproval(gen_info),
                src: PrefixSection(_),
                dst: Client { .. },
            } => Ok(self.handle_node_approval(gen_info)),
            _ => {
                self.handle_routing_message(msg, outbox)?;
                Ok(Transition::Stay)
            }
        }
    }

    fn handle_connection_response(&mut self, pub_id: PublicId) {
        self.peer_mgr.set_connected(pub_id);
        self.send_candidate_info(pub_id);
    }

    fn handle_node_approval(&mut self, gen_pfx_info: GenesisPfxInfo) -> Transition {
        self.resource_prover.handle_approval();
        info!(
            "{} Resource proof challenges completed. This node has been approved to join the \
             network!",
            self
        );

        Transition::IntoAdult { gen_pfx_info }
    }

    fn send_candidate_info(&mut self, pub_id: PublicId) {
        // We're not approved yet - we need to identify ourselves with our old and new IDs via
        // `CandidateInfo`. Serialise the old and new `PublicId`s and sign this using the old key.
        debug!("{} - Sending CandidateInfo to {:?}.", self, pub_id);

        let msg = {
            let old_public_id = *self.old_full_id.public_id();
            let new_public_id = *self.full_id.public_id();

            let both_ids = (old_public_id, new_public_id);
            let both_ids_serialised = match serialisation::serialise(&both_ids) {
                Ok(serialised) => serialised,
                Err(error) => {
                    error!("{} - Failed to serialise public IDs: {:?}", self, error);
                    return;
                }
            };
            let signature_using_old = self
                .old_full_id
                .ed_sign(&both_ids_serialised);

            let proxy_node_name = if let Some(name) = self.peer_mgr.get_proxy_name() {
                *name
            } else {
                warn!(
                    "{} - No proxy found, so unable to send CandidateInfo.",
                    self
                );
                return;
            };

            let new_client_auth = Authority::Client {
                client_id: new_public_id,
                proxy_node_name: proxy_node_name,
            };

            DirectMessage::CandidateInfo {
                old_public_id,
                signature_using_old,
                new_client_auth: new_client_auth,
            }
        };

        let _ = self.resource_proofing_status.insert(pub_id, false);

        self.send_direct_message(&pub_id, msg);
    }

    fn resend_info(&mut self, outbox: &mut dyn EventBox) -> Transition {
        let proxy_node_name = if let Some(proxy_node_name) = self.peer_mgr.get_proxy_name() {
            *proxy_node_name
        } else {
            warn!("{} No proxy found, cannot resend info.", self);
            return Transition::Stay;
        };
        let src = Authority::Client {
            client_id: *self.full_id.public_id(),
            proxy_node_name,
        };

        for (pub_id, resource_proofing) in self.resource_proofing_status.clone() {
            if !self.peer_mgr.is_connected(&pub_id) {
                let dst = Authority::ManagedNode(*pub_id.name());
                let _ = self.send_connection_request(pub_id, src, dst, outbox);
            } else if !resource_proofing {
                self.send_candidate_info(pub_id);
            }
        }
        self.resend_token = Some(self.timer.schedule(RESEND_TIMEOUT));
        Transition::Stay
    }

    #[cfg(feature = "mock_base")]
    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }
}

impl Base for ProvingNode {
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
        if let Authority::Client { ref client_id, .. } = *auth {
            client_id == self.full_id.public_id()
        } else {
            false
        }
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

    fn handle_timeout(&mut self, token: u64, outbox: &mut dyn EventBox) -> Transition {
        if self.resend_token == Some(token) {
            return self.resend_info(outbox);
        }

        let log_ident = self.log_ident();
        if let Some(transition) = self
            .resource_prover
            .handle_timeout(token, log_ident, outbox)
        {
            transition
        } else {
            Transition::Stay
        }
    }

    fn handle_resource_proof_result(&mut self, pub_id: PublicId, messages: Vec<DirectMessage>) {
        let msg = self
            .resource_prover
            .handle_action_res_proof(pub_id, messages);
        self.send_direct_message(&pub_id, msg);
    }

    fn handle_peer_lost(&mut self, pub_id: PublicId, outbox: &mut dyn EventBox) -> Transition {
        let _ = self.resource_proofing_status.remove(&pub_id);
        RelocatedNotEstablished::handle_peer_lost(self, pub_id, outbox)
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        self.check_direct_message_sender(&msg, &pub_id)?;

        use crate::messages::DirectMessage::*;
        match msg {
            ConnectionResponse => self.handle_connection_response(pub_id),
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
                if let Some(status) = self.resource_proofing_status.get_mut(&pub_id) {
                    *status = true;
                }
            }
            ResourceProofResponseReceipt => {
                if let Some(msg) = self.resource_prover.handle_receipt(pub_id) {
                    self.send_direct_message(&pub_id, msg);
                }
            }
            BootstrapRequest => self.handle_bootstrap_request(pub_id),
            _ => {
                debug!("{} Unhandled direct message: {:?}", self, msg);
            }
        }

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

impl Bootstrapped for ProvingNode {
    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }

    fn send_routing_message_impl(
        &mut self,
        routing_msg: RoutingMessage,
        expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message_via_proxy(routing_msg, expires_at)
    }
}

impl Relocated for ProvingNode {
    fn peer_mgr(&self) -> &PeerManager {
        &self.peer_mgr
    }

    fn peer_mgr_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_mgr
    }

    fn process_connection(&mut self, pub_id: PublicId, _: &mut dyn EventBox) {
        self.send_candidate_info(pub_id)
    }

    fn is_peer_valid(&self, _: &PublicId) -> bool {
        true
    }

    fn add_node_success(&mut self, _: &PublicId) {}

    fn add_node_failure(&mut self, pub_id: &PublicId) {
        self.disconnect_peer(pub_id)
    }

    fn send_event(&mut self, event: Event, _: &mut dyn EventBox) {
        self.event_backlog.push(event)
    }
}

impl BootstrappedNotEstablished for ProvingNode {
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
