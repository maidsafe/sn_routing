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
    action::Action,
    cache::Cache,
    error::RoutingError,
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, MessageContent, RoutingMessage},
    outbox::EventBox,
    peer_map::PeerMap,
    resource_prover::RESOURCE_PROOF_DURATION,
    routing_message_filter::RoutingMessageFilter,
    routing_table::{Authority, Prefix},
    state_machine::{State, Transition},
    time::{Duration, Instant},
    timer::Timer,
    types::MessageId,
    xor_name::XorName,
    NetworkService, XorTargetInterval,
};
use crossbeam_channel as mpmc;
use log::LogLevel;
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};

/// Total time to wait for `RelocateResponse`.
const RELOCATE_TIMEOUT: Duration = Duration::from_secs(60 + RESOURCE_PROOF_DURATION.as_secs());

pub struct RelocatingNodeDetails {
    pub action_sender: mpmc::Sender<Action>,
    pub cache: Box<Cache>,
    pub network_service: NetworkService,
    pub full_id: FullId,
    pub min_section_size: usize,
    pub peer_map: PeerMap,
    pub proxy_pub_id: PublicId,
    pub timer: Timer,
}

pub struct RelocatingNode {
    action_sender: mpmc::Sender<Action>,
    network_service: NetworkService,
    full_id: FullId,
    /// Only held here to be passed eventually to the `Node` state.
    cache: Box<Cache>,
    min_section_size: usize,
    peer_map: PeerMap,
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
            network_service: details.network_service,
            full_id: details.full_id,
            cache: details.cache,
            min_section_size: details.min_section_size,
            peer_map: details.peer_map,
            proxy_pub_id: details.proxy_pub_id,
            routing_msg_filter: RoutingMessageFilter::new(),
            relocation_timer_token,
            timer: details.timer,
        };

        debug!("{} State changed to RelocatingNode.", node);

        match node.relocate() {
            Ok(()) => Ok(node),
            Err(error) => {
                error!("{} Failed to start relocation: {:?}", node, error);
                Err(error)
            }
        }
    }

    pub fn into_bootstrapping(
        mut self,
        new_full_id: FullId,
        our_section: (Prefix<XorName>, BTreeSet<PublicId>),
        _outbox: &mut EventBox,
    ) -> State {
        // Disconnect from all currently connected peers.
        for peer in self.peer_map.remove_all() {
            self.network_service
                .service_mut()
                .disconnect_from(peer.peer_addr());
        }

        let target_state = TargetState::ProvingNode {
            old_full_id: self.full_id,
            our_section: our_section,
        };

        State::BootstrappingPeer(BootstrappingPeer::new(
            self.action_sender,
            self.cache,
            target_state,
            self.network_service,
            new_full_id,
            self.min_section_size,
            self.timer,
        ))
    }

    fn dispatch_routing_message(&mut self, routing_msg: RoutingMessage) -> Transition {
        use crate::messages::MessageContent::*;
        match routing_msg.content {
            Relocate { .. }
            | ExpectCandidate { .. }
            | ConnectionRequest { .. }
            | NeighbourInfo(..)
            | Merge(..)
            | UserMessage { .. }
            | NodeApproval { .. }
            | AckMessage(..) => {
                warn!(
                    "{} Not joined yet. Not handling {:?} from {:?} to {:?}",
                    self, routing_msg.content, routing_msg.src, routing_msg.dst
                );
            }
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
        target_interval: XorTargetInterval,
        section: (Prefix<XorName>, BTreeSet<PublicId>),
    ) -> Transition {
        let target_interval = target_interval.into();
        let new_id = FullId::within_range(&target_interval);
        if !section.0.matches(new_id.public_id().name()) {
            log_or_panic!(
                LogLevel::Error,
                "{} Invalid name chosen for {:?}. Range provided: {:?}",
                self,
                section.0,
                XorTargetInterval::new(target_interval)
            );
        }
        Transition::IntoBootstrapping {
            new_id: new_id,
            our_section: section,
        }
    }

    #[cfg(feature = "mock_base")]
    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }
}

impl Base for RelocatingNode {
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

    fn handle_timeout(&mut self, token: u64, outbox: &mut EventBox) -> Transition {
        if self.relocation_timer_token == token {
            info!(
                "{} - Failed to get relocated name from the network - restarting.",
                self
            );
            outbox.send_event(Event::RestartRequired);
            return Transition::Terminate;
        }
        Transition::Stay
    }

    fn handle_peer_lost(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        debug!("{} - Lost peer {}", self, pub_id);

        if self.proxy_pub_id == pub_id {
            debug!("{} - Lost bootstrap connection to {}.", self, pub_id);
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
        msg: HopMessage,
        _: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        if let Some(routing_msg) = self.filter_hop_message(msg)? {
            Ok(self.dispatch_routing_message(routing_msg))
        } else {
            Ok(Transition::Stay)
        }
    }
}

impl Bootstrapped for RelocatingNode {
    // Constructs a signed message, finds the node responsible for accumulation, and either sends
    // this node a signature or tries to accumulate signatures for this message (on success, the
    // accumulator handles or forwards the message).
    fn send_routing_message_impl(
        &mut self,
        routing_msg: RoutingMessage,
        expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message_via_proxy(routing_msg, expires_at)
    }

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl BootstrappedNotEstablished for RelocatingNode {
    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId, RoutingError> {
        proxied::get_proxy_public_id(self, &self.proxy_pub_id, proxy_name)
    }
}

impl Display for RelocatingNode {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "RelocatingNode({}())", self.name())
    }
}
