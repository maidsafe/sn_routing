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
    chain::{EldersInfo, GenesisPfxInfo, NetworkParams, SectionKeyInfo},
    error::{Result, RoutingError},
    event::{Connected, Event},
    id::FullId,
    location::{DstLocation, SrcLocation},
    messages::{
        BootstrapResponse, JoinRequest, Message, MessageWithBytes, QueuedMessage, Variant,
        VerifyStatus,
    },
    network_service::NetworkService,
    outbox::EventBox,
    relocation::RelocatePayload,
    rng::MainRng,
    routing_message_filter::RoutingMessageFilter,
    state_machine::{State, Transition},
    timer::Timer,
    xor_space::{Prefix, XorName},
};
use log::LogLevel;
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    time::Duration,
};

/// Time after which bootstrap is cancelled (and possibly retried).
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(600);

pub struct JoiningPeerDetails {
    pub network_service: NetworkService,
    pub full_id: FullId,
    pub network_cfg: NetworkParams,
    pub timer: Timer,
    pub rng: MainRng,
    pub elders_info: EldersInfo,
    pub relocate_payload: Option<RelocatePayload>,
}

// State of a node after bootstrapping, while joining a section
pub struct JoiningPeer {
    network_service: NetworkService,
    msg_filter: RoutingMessageFilter,
    msg_backlog: Vec<QueuedMessage>,
    full_id: FullId,
    timer: Timer,
    rng: MainRng,
    elders_info: EldersInfo,
    join_type: JoinType,
    network_cfg: NetworkParams,
}

impl JoiningPeer {
    pub fn new(details: JoiningPeerDetails) -> Self {
        let join_type = match details.relocate_payload {
            Some(payload) => JoinType::Relocate(payload),
            None => {
                let timeout_token = details.timer.schedule(JOIN_TIMEOUT);
                JoinType::First { timeout_token }
            }
        };

        let mut joining_peer = Self {
            network_service: details.network_service,
            msg_filter: RoutingMessageFilter::new(),
            msg_backlog: vec![],
            full_id: details.full_id,
            timer: details.timer,
            rng: details.rng,
            elders_info: details.elders_info,
            join_type,
            network_cfg: details.network_cfg,
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
            msg_backlog: self.msg_backlog,
            msg_filter: self.msg_filter,
            sig_accumulator: Default::default(),
            timer: self.timer,
            rng: self.rng,
            network_cfg: self.network_cfg,
        };
        let adult = Adult::new(details, Default::default(), outbox).map(State::Adult);

        let connect_type = match self.join_type {
            JoinType::First { .. } => Connected::First,
            JoinType::Relocate(_) => Connected::Relocate,
        };
        outbox.send_event(Event::Connected(connect_type));
        adult
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
            },
        )))
    }

    fn send_join_requests(&mut self) {
        let elders_version = self.elders_info.version();
        for dst in self.elders_info.clone().member_nodes() {
            info!("{} - Sending JoinRequest to {}", self, dst.public_id());

            let relocate_payload = match &self.join_type {
                JoinType::First { .. } => None,
                JoinType::Relocate(payload) => Some(payload.clone()),
            };
            let join_request = JoinRequest {
                elders_version,
                relocate_payload,
            };

            self.send_direct_message(
                dst.peer_addr(),
                Variant::JoinRequest(Box::new(join_request)),
            );
        }
    }

    fn handle_node_approval(&mut self, gen_pfx_info: GenesisPfxInfo) -> Transition {
        info!(
            "{} - This node has been approved to join the network at {:?}!",
            self,
            gen_pfx_info.latest_info.prefix(),
        );
        Transition::IntoAdult { gen_pfx_info }
    }

    fn verify_message_full(
        &self,
        msg: &Message,
        key_info: Option<&SectionKeyInfo>,
    ) -> Result<bool> {
        msg.verify(as_iter(key_info))
            .and_then(VerifyStatus::require_full)
            .map_err(|error| {
                self.log_verify_failure(msg, &error, as_iter(key_info));
                error
            })?;

        Ok(true)
    }

    #[cfg(feature = "mock_base")]
    pub fn process_timers(&mut self) {
        self.timer.process_timers()
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

    fn in_dst_location(&self, dst: &DstLocation) -> bool {
        match dst {
            DstLocation::Node(name) => name == self.name(),
            DstLocation::Section(_) | DstLocation::Prefix(_) => false,
            DstLocation::Direct => true,
        }
    }

    fn timer(&self) -> &Timer {
        &self.timer
    }

    fn rng(&mut self) -> &mut MainRng {
        &mut self.rng
    }

    fn handle_send_message(
        &mut self,
        _: SrcLocation,
        _: DstLocation,
        _: Vec<u8>,
    ) -> Result<(), RoutingError> {
        warn!("{} - Cannot handle SendMessage - not joined.", self);
        // TODO: return Err here eventually. Returning Ok for now to
        // preserve the pre-refactor behaviour.
        Ok(())
    }

    fn handle_timeout(&mut self, token: u64, _: &mut dyn EventBox) -> Transition {
        let join_token = match self.join_type {
            JoinType::First { timeout_token } => timeout_token,
            JoinType::Relocate(_) => return Transition::Stay,
        };

        if join_token == token {
            debug!("{} - Timeout when trying to join a section.", self);

            for addr in self
                .elders_info
                .member_nodes()
                .map(|node| *node.peer_addr())
            {
                self.network_service.disconnect(addr);
            }

            Transition::Rebootstrap
        } else {
            Transition::Stay
        }
    }

    fn handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: Message,
        _outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        match msg.variant {
            Variant::BootstrapResponse(BootstrapResponse::Join(info)) => {
                let p2p_node = msg.src.to_sender_node(sender)?;

                if info.version() > self.elders_info.version() {
                    if info.prefix().matches(self.name()) {
                        info!(
                            "{} - Newer Join response for our prefix {:?} from {:?}",
                            self, info, p2p_node
                        );
                        self.elders_info = info;
                        self.send_join_requests();
                    } else {
                        log_or_panic!(
                            LogLevel::Error,
                            "{} - Newer Join response not for our prefix {:?} from {:?}",
                            self,
                            info,
                            p2p_node,
                        );
                    }
                }
            }
            Variant::NodeApproval(gen_info) => {
                // Ensure src and dst are what we expect.
                let _: &Prefix<_> = msg.src.as_section()?;
                let _: &XorName = msg.dst.as_node()?;

                return Ok(self.handle_node_approval(*gen_info));
            }
            _ => unreachable!(),
        }

        Ok(Transition::Stay)
    }

    fn unhandled_message(&mut self, sender: Option<SocketAddr>, msg: Message) {
        match msg.variant {
            Variant::BootstrapResponse(_) => (),
            _ => {
                debug!("{} Unhandled message, adding to backlog: {:?}", self, msg,);
                self.msg_backlog.push(msg.into_queued(sender));
            }
        }
    }

    fn should_handle_message(&self, msg: &Message) -> bool {
        match msg.variant {
            Variant::BootstrapResponse(BootstrapResponse::Join(_)) | Variant::NodeApproval(_) => {
                true
            }
            Variant::NeighbourInfo(_)
            | Variant::UserMessage(_)
            | Variant::AckMessage { .. }
            | Variant::GenesisUpdate(_)
            | Variant::Relocate(_)
            | Variant::MessageSignature(_)
            | Variant::BootstrapRequest(_)
            | Variant::BootstrapResponse(_)
            | Variant::JoinRequest(_)
            | Variant::MemberKnowledge { .. }
            | Variant::ParsecRequest(..)
            | Variant::ParsecResponse(..)
            | Variant::Ping => false,
        }
    }

    fn filter_incoming_message(&mut self, msg: &MessageWithBytes) -> bool {
        self.msg_filter.filter_incoming(msg).is_new()
    }

    fn relay_message(&mut self, msg: &MessageWithBytes) -> Result<()> {
        self.msg_backlog
            .push(msg.clone_or_deserialize_message()?.into_queued(None));
        Ok(())
    }

    fn verify_message(&self, msg: &Message) -> Result<bool> {
        match (&msg.variant, &self.join_type) {
            (Variant::NodeApproval(_), JoinType::Relocate(payload)) => {
                let details = payload.relocate_details();
                let key_info = &details.destination_key_info;
                self.verify_message_full(msg, Some(key_info))
            }
            (Variant::NodeApproval(_), JoinType::First { .. }) => {
                // We don't have any trusted keys to verify this message, but we still need to
                // handle it.
                Ok(true)
            }
            (Variant::BootstrapResponse(BootstrapResponse::Join(_)), _) => {
                self.verify_message_full(msg, None)
            }
            _ => unreachable!(),
        }
    }
}

impl Display for JoiningPeer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "JoiningPeer({})", self.name())
    }
}

#[allow(clippy::large_enum_variant)]
enum JoinType {
    // Node joining the network for the first time.
    First { timeout_token: u64 },
    // Node being relocated.
    Relocate(RelocatePayload),
}

fn as_iter(
    key_info: Option<&SectionKeyInfo>,
) -> impl Iterator<Item = (&Prefix<XorName>, &SectionKeyInfo)> {
    key_info
        .into_iter()
        .map(|key_info| (key_info.prefix(), key_info))
}
