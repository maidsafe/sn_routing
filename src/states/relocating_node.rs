// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    common::{proxied, Base, Bootstrapped, BootstrappedNotEstablished},
    BootstrappingPeer, TargetState,
};
use crate::{
    ack_manager::{Ack, AckManager},
    cache::Cache,
    chain::SectionInfo,
    error::RoutingError,
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, MessageContent, RoutingMessage},
    outbox::EventBox,
    resource_prover::RESOURCE_PROOF_DURATION,
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix},
    state_machine::{State, Transition},
    time::{Duration, Instant},
    timer::Timer,
    types::{MessageId, RoutingActionSender},
    xor_name::XorName,
    CrustEvent, CrustEventSender, Service,
};
use log::LogLevel;
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
    sync::mpsc::Receiver,
};

/// Total time to wait for `RelocateResponse`.
const RELOCATE_TIMEOUT: Duration = Duration::from_secs(60 + RESOURCE_PROOF_DURATION.as_secs());

pub struct RelocatingNodeDetails {
    pub action_sender: RoutingActionSender,
    pub cache: Box<Cache>,
    pub crust_service: Service,
    pub full_id: FullId,
    pub min_section_size: usize,
    pub proxy_pub_id: PublicId,
    pub timer: Timer,
}

pub struct RelocatingNode {
    action_sender: RoutingActionSender,
    ack_mgr: AckManager,
    crust_service: Service,
    full_id: FullId,
    /// Only held here to be passed eventually to the `Node` state.
    cache: Box<Cache>,
    min_section_size: usize,
    proxy_pub_id: PublicId,
    /// The queue of routing messages addressed to us. These do not themselves need forwarding,
    /// although they may wrap a message which needs forwarding.
    routing_msg_filter: RoutingMessageFilter,
    relocation_timer_token: u64,
    timer: Timer,
}

impl RelocatingNode {
    pub fn from_bootstrapping(details: RelocatingNodeDetails) -> Result<Self, RoutingError> {
        let relocation_timer_token = details.timer.schedule(RELOCATE_TIMEOUT);
        let mut node = Self {
            action_sender: details.action_sender,
            ack_mgr: AckManager::new(),
            crust_service: details.crust_service,
            full_id: details.full_id,
            cache: details.cache,
            min_section_size: details.min_section_size,
            proxy_pub_id: details.proxy_pub_id,
            routing_msg_filter: RoutingMessageFilter::new(),
            relocation_timer_token,
            timer: details.timer,
        };

        match node.relocate() {
            Ok(()) => {
                debug!("{} State changed to RelocatingNode.", node);
                Ok(node)
            }
            Err(error) => {
                error!("{} Failed to start relocation: {:?}", node, error);
                Err(error)
            }
        }
    }

    pub fn into_bootstrapping(
        self,
        crust_rx: &mut Receiver<CrustEvent<PublicId>>,
        crust_sender: CrustEventSender,
        new_full_id: FullId,
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
        outbox: &mut EventBox,
    ) -> Result<State, RoutingError> {
        let service = Self::start_new_crust_service(
            self.crust_service,
            *new_full_id.public_id(),
            crust_rx,
            crust_sender,
        );
        let target_state = TargetState::ProvingNode {
            old_full_id: self.full_id,
            our_section: our_section,
        };

        match BootstrappingPeer::new(
            self.action_sender,
            self.cache,
            target_state,
            service,
            new_full_id,
            self.min_section_size,
            self.timer,
        ) {
            Ok(peer) => Ok(State::BootstrappingPeer(peer)),
            Err(error) => {
                outbox.send_event(Event::RestartRequired);
                Err(error)
            }
        }
    }

    #[cfg(not(feature = "mock_base"))]
    fn start_new_crust_service(
        old_crust_service: Service,
        pub_id: PublicId,
        crust_rx: &mut Receiver<CrustEvent<PublicId>>,
        crust_sender: CrustEventSender,
    ) -> Service {
        // Drop the current Crust service and flush the receiver
        drop(old_crust_service);
        while let Ok(_crust_event) = crust_rx.try_recv() {}

        let mut crust_service = match Service::new(crust_sender, pub_id) {
            Ok(service) => service,
            Err(error) => panic!("Unable to start crust::Service {:?}", error),
        };
        crust_service.start_service_discovery();
        crust_service
    }

    #[cfg(feature = "mock_base")]
    fn start_new_crust_service(
        old_crust_service: Service,
        pub_id: PublicId,
        _crust_rx: &mut Receiver<CrustEvent<PublicId>>,
        crust_sender: CrustEventSender,
    ) -> Service {
        old_crust_service.restart(crust_sender, pub_id);
        old_crust_service
    }

    fn dispatch_routing_message(&mut self, routing_msg: RoutingMessage) -> Transition {
        use crate::messages::MessageContent::*;
        match routing_msg.content {
            Relocate { .. }
            | ExpectCandidate { .. }
            | ConnectionInfoRequest { .. }
            | ConnectionInfoResponse { .. }
            | NeighbourInfo(..)
            | NeighbourConfirm(..)
            | Merge(..)
            | UserMessagePart { .. }
            | NodeApproval { .. } => {
                warn!(
                    "{} Not joined yet. Not handling {:?} from {:?} to {:?}",
                    self, routing_msg.content, routing_msg.src, routing_msg.dst
                );
            }
            Ack(ack, _) => self.handle_ack_response(ack),
            RelocateResponse {
                target_interval,
                section,
                ..
            } => {
                return self.handle_relocate_response(target_interval, section);
            }
        }
        Transition::Stay
    }

    fn relocate(&mut self) -> Result<(), RoutingError> {
        let request_content = MessageContent::Relocate {
            message_id: MessageId::new(),
        };
        let src = Authority::Client {
            client_id: *self.full_id.public_id(),
            proxy_node_name: *self.proxy_pub_id.name(),
        };
        let dst = Authority::Section(*self.name());

        info!(
            "{} Requesting a relocated name from the network. This can take a while.",
            self
        );

        self.send_routing_message(src, dst, request_content)
    }

    fn handle_relocate_response(
        &mut self,
        target_interval: (XorName, XorName),
        section: (Prefix<XorName>, BTreeSet<PublicId>),
    ) -> Transition {
        let new_id = FullId::within_range(&target_interval.0, &target_interval.1);
        if !section.0.matches(new_id.public_id().name()) {
            log_or_panic!(
                LogLevel::Error,
                "{} Invalid name chosen for {:?}. Range provided: {:?}",
                self,
                section.0,
                target_interval
            );
        }
        Transition::IntoBootstrapping {
            new_id: new_id,
            our_section: section,
        }
    }

    fn handle_ack_response(&mut self, ack: Ack) {
        self.ack_mgr.receive(ack);
    }

    #[cfg(feature = "mock_base")]
    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }
}

impl Base for RelocatingNode {
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
        if self.relocation_timer_token == token {
            info!(
                "{} - Failed to get relocated name from the network - restarting.",
                self
            );
            outbox.send_event(Event::RestartRequired);
            return Transition::Terminate;
        }
        self.resend_unacknowledged_timed_out_msgs(token);
        Transition::Stay
    }

    fn handle_lost_peer(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        debug!("{} Received LostPeer - {}", self, pub_id);

        if self.proxy_pub_id == pub_id {
            debug!("{} Lost bootstrap connection to {}.", self, pub_id);
            outbox.send_event(Event::Terminated);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        _: PublicId,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        debug!("{} - Unhandled direct message: {:?}", self, msg);
        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        hop_msg: HopMessage,
        pub_id: PublicId,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        if self.proxy_pub_id != pub_id {
            return Err(RoutingError::UnknownConnection(pub_id));
        }

        if let Some(routing_msg) = self.filter_hop_message(hop_msg, pub_id)? {
            Ok(self.dispatch_routing_message(routing_msg))
        } else {
            Ok(Transition::Stay)
        }
    }
}

impl Bootstrapped for RelocatingNode {
    fn ack_mgr(&self) -> &AckManager {
        &self.ack_mgr
    }

    fn ack_mgr_mut(&mut self) -> &mut AckManager {
        &mut self.ack_mgr
    }

    // Constructs a signed message, finds the node responsible for accumulation, and either sends
    // this node a signature or tries to accumulate signatures for this message (on success, the
    // accumulator handles or forwards the message).
    fn send_routing_message_via_route(
        &mut self,
        routing_msg: RoutingMessage,
        src_section: Option<SectionInfo>,
        route: u8,
        expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message_via_proxy(routing_msg, src_section, route, expires_at)
    }

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl BootstrappedNotEstablished for RelocatingNode {
    const SEND_ACK: bool = true;

    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId, RoutingError> {
        proxied::get_proxy_public_id(self, &self.proxy_pub_id, proxy_name)
    }
}

impl Display for RelocatingNode {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "RelocatingNode({}())", self.name())
    }
}
