// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::common::{
    proxied, Base, Bootstrapped, BootstrappedNotEstablished, USER_MSG_CACHE_EXPIRY_DURATION,
};
use crate::{
    ack_manager::{Ack, AckManager, UnacknowledgedMessage},
    chain::SectionInfo,
    error::{InterfaceError, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    messages::{
        DirectMessage, HopMessage, MessageContent, Request, RoutingMessage, UserMessage,
        UserMessageCache,
    },
    outbox::EventBox,
    peer_map::PeerMap,
    routing_message_filter::RoutingMessageFilter,
    routing_table::Authority,
    state_machine::Transition,
    time::{Duration, Instant},
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
};

/// Duration to wait before sending rate limit exceeded messages.
pub const RATE_EXCEED_RETRY: Duration = Duration::from_millis(800);

pub struct ClientDetails {
    pub network_service: NetworkService,
    pub full_id: FullId,
    pub min_section_size: usize,
    pub msg_expiry_dur: Duration,
    pub peer_map: PeerMap,
    pub proxy_pub_id: PublicId,
    pub timer: Timer,
}

/// A node connecting a user to the network, as opposed to a routing / data storage node.
///
/// Each client has a _proxy_: a node through which all requests are routed.
pub struct Client {
    ack_mgr: AckManager,
    network_service: NetworkService,
    full_id: FullId,
    min_section_size: usize,
    peer_map: PeerMap,
    proxy_pub_id: PublicId,
    routing_msg_filter: RoutingMessageFilter,
    timer: Timer,
    user_msg_cache: UserMessageCache,
    resend_buf: BTreeMap<u64, UnacknowledgedMessage>,
    msg_expiry_dur: Duration,
}

impl Client {
    pub fn from_bootstrapping(details: ClientDetails, outbox: &mut EventBox) -> Self {
        let client = Client {
            ack_mgr: AckManager::new(),
            network_service: details.network_service,
            full_id: details.full_id,
            min_section_size: details.min_section_size,
            peer_map: details.peer_map,
            proxy_pub_id: details.proxy_pub_id,
            routing_msg_filter: RoutingMessageFilter::new(),
            timer: details.timer,
            user_msg_cache: UserMessageCache::with_expiry_duration(USER_MSG_CACHE_EXPIRY_DURATION),
            resend_buf: Default::default(),
            msg_expiry_dur: details.msg_expiry_dur,
        };

        debug!("{} State changed to Client.", client);

        outbox.send_event(Event::Connected);
        client
    }

    fn handle_ack_response(&mut self, ack: Ack) -> Transition {
        self.ack_mgr.receive(ack);
        Transition::Stay
    }

    fn dispatch_routing_message(
        &mut self,
        routing_msg: RoutingMessage,
        outbox: &mut EventBox,
    ) -> Transition {
        match routing_msg.content {
            MessageContent::Ack(ack, _) => self.handle_ack_response(ack),
            MessageContent::UserMessagePart {
                hash,
                part_count,
                part_index,
                payload,
                ..
            } => {
                trace!(
                    "{} Got UserMessagePart {:02x}{:02x}{:02x}.., {}/{} from {:?} to {:?}.",
                    self,
                    hash[0],
                    hash[1],
                    hash[2],
                    part_index + 1,
                    part_count,
                    routing_msg.src,
                    routing_msg.dst
                );
                if let Some(msg) = self
                    .user_msg_cache
                    .add(hash, part_count, part_index, payload)
                {
                    outbox.send_event(msg.into_event(routing_msg.src, routing_msg.dst));
                }
                Transition::Stay
            }
            content => {
                debug!(
                    "{} Unhandled routing message: {:?} from {:?} to {:?}",
                    self, content, routing_msg.src, routing_msg.dst
                );
                Transition::Stay
            }
        }
    }

    /// Sends the given message, possibly splitting it up into smaller parts.
    fn send_user_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        user_msg: UserMessage,
        priority: u8,
    ) -> Result<(), RoutingError> {
        let parts = user_msg.to_parts(priority)?;
        let msg_expiry_dur = self.msg_expiry_dur;
        for part in parts {
            self.send_routing_message_with_expiry(
                src,
                dst,
                part,
                Some(Instant::now() + msg_expiry_dur),
            )?;
        }
        Ok(())
    }
}

impl Base for Client {
    fn network_service(&self) -> &NetworkService {
        &self.network_service
    }

    fn network_service_mut(&mut self) -> &mut NetworkService {
        &mut self.network_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    /// Does the given authority represent us?
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

    fn handle_client_send_request(
        &mut self,
        dst: Authority<XorName>,
        content: Request,
        priority: u8,
    ) -> Result<(), InterfaceError> {
        let src = Authority::Client {
            client_id: *self.full_id.public_id(),
            proxy_node_name: *self.proxy_pub_id.name(),
        };
        let user_msg = UserMessage::Request(content);

        match self.send_user_message(src, dst, user_msg, priority) {
            Err(RoutingError::Interface(err)) => Err(err),
            Err(_) | Ok(_) => Ok(()),
        }
    }

    fn handle_timeout(&mut self, token: u64, _: &mut EventBox) -> Transition {
        let proxy_pub_id = self.proxy_pub_id;

        // Check if token corresponds to a rate limit exceeded msg.
        if let Some(unacked_msg) = self.resend_buf.remove(&token) {
            if unacked_msg.expires_at.map_or(false, |i| i < Instant::now()) {
                return Transition::Stay;
            }

            self.routing_msg_filter().remove_from_outgoing_filter(
                &unacked_msg.routing_msg,
                &proxy_pub_id,
                unacked_msg.route,
            );
            if let Err(error) = self.send_routing_message_via_route(
                unacked_msg.routing_msg,
                unacked_msg.src_section,
                unacked_msg.route,
                unacked_msg.expires_at,
            ) {
                debug!("{} Failed to send message: {:?}", self, error);
            }

            return Transition::Stay;
        }

        // Check if token corresponds to an unacknowledged msg.
        self.resend_unacknowledged_timed_out_msgs(token);
        Transition::Stay
    }

    fn handle_peer_disconnected(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        debug!("{} - Disconnected from {:?}", self, pub_id);

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
        if let DirectMessage::ProxyRateLimitExceeded { ack } = msg {
            if let Some(unack_msg) = self.ack_mgr.remove(&ack) {
                let token = self.timer().schedule(RATE_EXCEED_RETRY);
                let _ = self.resend_buf.insert(token, unack_msg);
            } else {
                debug!(
                    "{} Got ProxyRateLimitExceeded, but no corresponding request found",
                    self
                );
            }
        } else {
            debug!("{} Unhandled direct message: {:?}", self, msg);
        }
        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        if self.proxy_pub_id != pub_id {
            return Err(RoutingError::UnknownConnection(pub_id));
        }

        if let Some(routing_msg) = self.filter_hop_message(msg)? {
            Ok(self.dispatch_routing_message(routing_msg, outbox))
        } else {
            Ok(Transition::Stay)
        }
    }
}

impl Bootstrapped for Client {
    fn ack_mgr(&self) -> &AckManager {
        &self.ack_mgr
    }

    fn ack_mgr_mut(&mut self) -> &mut AckManager {
        &mut self.ack_mgr
    }

    fn resend_unacknowledged_timed_out_msgs(&mut self, token: u64) {
        if let Some((unacked_msg, ack)) = self.ack_mgr.find_timed_out(token) {
            trace!(
                "{} Timed out waiting for {:?}: {:?}",
                self,
                ack,
                unacked_msg
            );

            let msg_expired = unacked_msg.expires_at.map_or(false, |i| i < Instant::now());
            if msg_expired || unacked_msg.route as usize == self.min_section_size {
                debug!(
                    "{} Message unable to be acknowledged - giving up. {:?}",
                    self, unacked_msg
                );
            } else if let Err(error) = self.send_routing_message_via_route(
                unacked_msg.routing_msg,
                unacked_msg.src_section,
                unacked_msg.route,
                unacked_msg.expires_at,
            ) {
                debug!("{} Failed to send message: {:?}", self, error);
            }
        }
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

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl BootstrappedNotEstablished for Client {
    const SEND_ACK: bool = false;

    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId, RoutingError> {
        proxied::get_proxy_public_id(self, &self.proxy_pub_id, proxy_name)
    }
}

#[cfg(feature = "mock_base")]
impl Client {
    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }
}

impl Display for Client {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Client({})", self.name())
    }
}
