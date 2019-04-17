// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::common::{Base, Bootstrapped, Unapproved};
use super::{Bootstrapping, BootstrappingTargetState};
use crate::ack_manager::{Ack, AckManager};
use crate::action::Action;
use crate::cache::Cache;
use crate::chain::SectionInfo;
use crate::error::{InterfaceError, Result, RoutingError};
use crate::event::Event;
use crate::id::{FullId, PublicId};
use crate::messages::{HopMessage, Message, MessageContent, RoutingMessage};
use crate::outbox::EventBox;
use crate::resource_prover::RESOURCE_PROOF_DURATION_SECS;
use crate::routing_message_filter::RoutingMessageFilter;
use crate::routing_table::{Authority, Prefix};
use crate::state_machine::{State, Transition};
use crate::time::{Duration, Instant};
use crate::timer::Timer;
use crate::types::{MessageId, RoutingActionSender};
use crate::xor_name::XorName;
use crate::{CrustEvent, CrustEventSender, Service};
use log::LogLevel;
use maidsafe_utilities::serialisation;
use std::collections::BTreeSet;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::mpsc::Receiver;

/// Total time (in seconds) to wait for `RelocateResponse`.
const RELOCATE_TIMEOUT_SECS: u64 = 60 + RESOURCE_PROOF_DURATION_SECS;

pub struct JoiningNode {
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

impl JoiningNode {
    #[allow(clippy::too_many_arguments)]
    pub fn from_bootstrapping(
        action_sender: RoutingActionSender,
        cache: Box<Cache>,
        crust_service: Service,
        full_id: FullId,
        min_section_size: usize,
        proxy_pub_id: PublicId,
        timer: Timer,
    ) -> Option<Self> {
        let duration = Duration::from_secs(RELOCATE_TIMEOUT_SECS);
        let relocation_timer_token = timer.schedule(duration);
        let mut joining_node = JoiningNode {
            action_sender: action_sender,
            ack_mgr: AckManager::new(),
            crust_service: crust_service,
            full_id: full_id,
            cache: cache,
            min_section_size: min_section_size,
            proxy_pub_id: proxy_pub_id,
            routing_msg_filter: RoutingMessageFilter::new(),
            relocation_timer_token: relocation_timer_token,
            timer: timer,
        };

        if let Err(error) = joining_node.relocate() {
            error!("{} Failed to start relocation: {:?}", joining_node, error);
            None
        } else {
            debug!("{} State changed to joining node.", joining_node);
            Some(joining_node)
        }
    }

    pub fn handle_action(&mut self, action: Action, outbox: &mut EventBox) -> Transition {
        match action {
            Action::ClientSendRequest { ref result_tx, .. }
            | Action::NodeSendMessage { ref result_tx, .. } => {
                warn!("{} Cannot handle {:?} - not joined.", self, action);
                let _ = result_tx.send(Err(InterfaceError::InvalidState));
            }
            Action::Id { result_tx } => {
                let _ = result_tx.send(*self.id());
            }
            Action::Timeout(token) => {
                if let Transition::Terminate = self.handle_timeout(token, outbox) {
                    return Transition::Terminate;
                }
            }
            Action::ResourceProofResult(..) => {
                warn!("{} Cannot handle {:?} - not joined.", self, action);
            }
            Action::Terminate => {
                return Transition::Terminate;
            }
        }
        Transition::Stay
    }

    pub fn handle_crust_event(
        &mut self,
        crust_event: CrustEvent<PublicId>,
        outbox: &mut EventBox,
    ) -> Transition {
        match crust_event {
            CrustEvent::LostPeer(pub_id) => self.handle_lost_peer(pub_id, outbox),
            CrustEvent::NewMessage(pub_id, _, bytes) => self.handle_new_message(pub_id, bytes),
            _ => {
                debug!("{} - Unhandled crust event: {:?}", self, crust_event);
                Transition::Stay
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
    ) -> State {
        let service = Self::start_new_crust_service(
            self.crust_service,
            *new_full_id.public_id(),
            crust_rx,
            crust_sender,
        );
        let target_state = BootstrappingTargetState::ProvingNode {
            old_full_id: self.full_id,
            our_section: our_section,
        };
        if let Some(bootstrapping) = Bootstrapping::new(
            self.action_sender,
            self.cache,
            target_state,
            service,
            new_full_id,
            self.min_section_size,
            self.timer,
        ) {
            State::Bootstrapping(bootstrapping)
        } else {
            outbox.send_event(Event::RestartRequired);
            State::Terminated
        }
    }

    #[cfg(not(feature = "mock"))]
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

    #[cfg(feature = "mock")]
    fn start_new_crust_service(
        old_crust_service: Service,
        pub_id: PublicId,
        _crust_rx: &mut Receiver<CrustEvent<PublicId>>,
        crust_sender: CrustEventSender,
    ) -> Service {
        old_crust_service.restart(crust_sender, pub_id);
        old_crust_service
    }

    fn handle_new_message(&mut self, pub_id: PublicId, bytes: Vec<u8>) -> Transition {
        let transition = match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(hop_msg)) => self.handle_hop_message(hop_msg, pub_id),
            Ok(message) => {
                debug!("{} - Unhandled new message: {:?}", self, message);
                Ok(Transition::Stay)
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        };

        match transition {
            Ok(transition) => transition,
            Err(RoutingError::FilterCheckFailed) => Transition::Stay,
            Err(error) => {
                debug!("{} - {:?}", self, error);
                Transition::Stay
            }
        }
    }

    fn handle_hop_message(&mut self, hop_msg: HopMessage, pub_id: PublicId) -> Result<Transition> {
        if self.proxy_pub_id != pub_id {
            return Err(RoutingError::UnknownConnection(pub_id));
        }

        if let Some(routing_msg) = self.filter_hop_message(hop_msg, pub_id)? {
            Ok(self.dispatch_routing_message(routing_msg))
        } else {
            Ok(Transition::Stay)
        }
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
            | AcceptAsCandidate { .. }
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

    fn relocate(&mut self) -> Result<()> {
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

    fn handle_timeout(&mut self, token: u64, outbox: &mut EventBox) -> Transition {
        if self.relocation_timer_token == token {
            info!(
                "{} Failed to get relocated name from the network, so restarting.",
                self
            );
            outbox.send_event(Event::RestartRequired);
            return Transition::Terminate;
        }
        self.resend_unacknowledged_timed_out_msgs(token);
        Transition::Stay
    }

    #[cfg(feature = "mock")]
    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }
}

impl Base for JoiningNode {
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

    fn handle_lost_peer(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        debug!("{} Received LostPeer - {}", self, pub_id);

        if self.proxy_pub_id == pub_id {
            debug!("{} Lost bootstrap connection to {}.", self, pub_id);
            outbox.send_event(Event::Terminate);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn min_section_size(&self) -> usize {
        self.min_section_size
    }
}

impl Bootstrapped for JoiningNode {
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
    ) -> Result<()> {
        self.send_routing_message_via_proxy(routing_msg, src_section, route, expires_at)
    }

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl Unapproved for JoiningNode {
    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId> {
        if self.proxy_pub_id.name() == proxy_name {
            Ok(&self.proxy_pub_id)
        } else {
            error!("{} Unable to find connection to proxy node.", self);
            Err(RoutingError::ProxyConnectionNotFound)
        }
    }
}

impl Display for JoiningNode {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "JoiningNode({}())", self.name())
    }
}
