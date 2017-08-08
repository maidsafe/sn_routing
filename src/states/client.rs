// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::common::{Base, Bootstrapped, USER_MSG_CACHE_EXPIRY_DURATION_SECS};
use {CrustEvent, Service};
use ack_manager::{Ack, AckManager, UnacknowledgedMessage};
use action::Action;
use error::{InterfaceError, RoutingError};
use event::Event;
#[cfg(feature = "use-mock-crust")]
use fake_clock::FakeClock as Instant;
use id::{FullId, PublicId};
use maidsafe_utilities::serialisation;
use messages::{DirectMessage, HopMessage, Message, MessageContent, RoutingMessage, SignedMessage,
               UserMessage, UserMessageCache};
use outbox::EventBox;
use routing_message_filter::{FilteringResult, RoutingMessageFilter};
use routing_table::Authority;
use state_machine::Transition;
use stats::Stats;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;
#[cfg(not(feature = "use-mock-crust"))]
use std::time::Instant;
use timer::Timer;
use xor_name::XorName;

/// Duration to wait before sending rate limit exceeded messages.
pub const RATE_EXCEED_RETRY_MS: u64 = 800;

/// A node connecting a user to the network, as opposed to a routing / data storage node.
///
/// Each client has a _proxy_: a node through which all requests are routed.
pub struct Client {
    ack_mgr: AckManager,
    crust_service: Service,
    full_id: FullId,
    min_section_size: usize,
    proxy_pub_id: PublicId,
    routing_msg_filter: RoutingMessageFilter,
    stats: Stats,
    timer: Timer,
    user_msg_cache: UserMessageCache,
    resend_buf: BTreeMap<u64, UnacknowledgedMessage>,
    msg_expiry_dur: Duration,
}

impl Client {
    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn from_bootstrapping(
        crust_service: Service,
        full_id: FullId,
        min_section_size: usize,
        proxy_pub_id: PublicId,
        stats: Stats,
        timer: Timer,
        msg_expiry_dur: Duration,
        outbox: &mut EventBox,
    ) -> Self {
        let client = Client {
            ack_mgr: AckManager::new(),
            crust_service: crust_service,
            full_id: full_id,
            min_section_size: min_section_size,
            proxy_pub_id: proxy_pub_id,
            routing_msg_filter: RoutingMessageFilter::new(),
            stats: stats,
            timer: timer,
            user_msg_cache: UserMessageCache::with_expiry_duration(
                Duration::from_secs(USER_MSG_CACHE_EXPIRY_DURATION_SECS),
            ),
            resend_buf: Default::default(),
            msg_expiry_dur: msg_expiry_dur,
        };

        debug!("{:?} State changed to client.", client);

        outbox.send_event(Event::Connected);
        client
    }

    pub fn handle_action(&mut self, action: Action) -> Transition {
        match action {
            Action::ClientSendRequest {
                content,
                dst,
                priority,
                result_tx,
            } => {
                let src = Authority::Client {
                    client_id: *self.full_id.public_id(),
                    proxy_node_name: *self.proxy_pub_id.name(),
                };

                let user_msg = UserMessage::Request(content);
                let result = match self.send_user_message(src, dst, user_msg, priority) {
                    Err(RoutingError::Interface(err)) => Err(err),
                    Err(_) | Ok(_) => Ok(()),
                };

                let _ = result_tx.send(result);
            }
            Action::NodeSendMessage { result_tx, .. } => {
                let _ = result_tx.send(Err(InterfaceError::InvalidState));
            }
            Action::Id { result_tx } => {
                let _ = result_tx.send(*self.id());
            }
            Action::Timeout(token) => self.handle_timeout(token),
            Action::ResourceProofResult(..) => {
                error!("Action::ResourceProofResult received by Client state");
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
            CrustEvent::NewMessage(pub_id, _, bytes) => {
                self.handle_new_message(pub_id, bytes, outbox)
            }
            _ => {
                debug!("{:?} Unhandled crust event {:?}", self, crust_event);
                Transition::Stay
            }
        }
    }

    fn handle_ack_response(&mut self, ack: Ack) -> Transition {
        self.ack_mgr.receive(ack);
        Transition::Stay
    }

    fn handle_timeout(&mut self, token: u64) {
        let proxy_pub_id = self.proxy_pub_id;

        // Check if token corresponds to a rate limit exceeded msg.
        if let Some(unacked_msg) = self.resend_buf.remove(&token) {
            if unacked_msg.expires_at.map_or(false, |i| i < Instant::now()) {
                return;
            }

            self.routing_msg_filter().remove_from_outgoing_filter(
                &unacked_msg.routing_msg,
                &proxy_pub_id,
                unacked_msg.route,
            );
            if let Err(error) = self.send_routing_message_via_route(
                unacked_msg.routing_msg,
                unacked_msg.route,
                unacked_msg.expires_at,
            )
            {
                debug!("{:?} Failed to send message: {:?}", self, error);
            } else {
                self.stats.increase_user_msg_part();
            }
            return;
        }

        // Check if token corresponds to an unacknowledged msg.
        self.resend_unacknowledged_timed_out_msgs(token)
    }

    fn handle_new_message(
        &mut self,
        pub_id: PublicId,
        bytes: Vec<u8>,
        outbox: &mut EventBox,
    ) -> Transition {
        let transition = match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(hop_msg)) => self.handle_hop_message(hop_msg, pub_id, outbox),
            Ok(Message::Direct(direct_msg)) => self.handle_direct_message(direct_msg),
            Ok(message) => {
                debug!("{:?} Unhandled new message: {:?}", self, message);
                Ok(Transition::Stay)
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        };

        match transition {
            Ok(transition) => transition,
            Err(RoutingError::FilterCheckFailed) => Transition::Stay,
            Err(error) => {
                debug!("{:?} {:?}", self, error);
                Transition::Stay
            }
        }
    }

    fn handle_hop_message(
        &mut self,
        hop_msg: HopMessage,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        if self.proxy_pub_id == pub_id {
            hop_msg.verify(self.proxy_pub_id.signing_public_key())?;
        } else {
            return Err(RoutingError::UnknownConnection(pub_id));
        }

        let signed_msg = hop_msg.content;
        signed_msg.check_integrity(self.min_section_size())?;

        let routing_msg = signed_msg.into_routing_message();
        let in_authority = self.in_authority(&routing_msg.dst);

        // Prevents us repeatedly handling identical messages sent by a malicious peer.
        match self.routing_msg_filter.filter_incoming(
            &routing_msg,
            hop_msg.route,
        ) {
            FilteringResult::KnownMessage |
            FilteringResult::KnownMessageAndRoute => return Err(RoutingError::FilterCheckFailed),
            FilteringResult::NewMessage => (),
        }

        if !in_authority {
            return Ok(Transition::Stay);
        }

        Ok(self.dispatch_routing_message(routing_msg, outbox))
    }

    fn handle_direct_message(
        &mut self,
        direct_msg: DirectMessage,
    ) -> Result<Transition, RoutingError> {
        if let DirectMessage::ProxyRateLimitExceeded { ack } = direct_msg {
            if let Some(unack_msg) = self.ack_mgr.remove(&ack) {
                let token = self.timer().schedule(
                    Duration::from_millis(RATE_EXCEED_RETRY_MS),
                );
                let _ = self.resend_buf.insert(token, unack_msg);
            } else {
                debug!(
                    "{:?} Got ProxyRateLimitExceeded, but no corresponding request found",
                    self
                );
            }
        } else {
            debug!("{:?} Unhandled direct message: {:?}", self, direct_msg);
        }
        Ok(Transition::Stay)
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
                    "{:?} Got UserMessagePart {:02x}{:02x}{:02x}.., {}/{} from {:?} to {:?}.",
                    self,
                    hash[0],
                    hash[1],
                    hash[2],
                    part_index + 1,
                    part_count,
                    routing_msg.src,
                    routing_msg.dst
                );
                self.stats.increase_user_msg_part();
                if let Some(msg) = self.user_msg_cache.add(
                    hash,
                    part_count,
                    part_index,
                    payload,
                )
                {
                    self.stats().count_user_message(&msg);
                    outbox.send_event(msg.into_event(routing_msg.src, routing_msg.dst));
                }
                Transition::Stay
            }
            content => {
                debug!(
                    "{:?} Unhandled routing message: {:?} from {:?} to {:?}",
                    self,
                    content,
                    routing_msg.src,
                    routing_msg.dst
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
        self.stats.count_user_message(&user_msg);
        let parts = user_msg.to_parts(priority)?;
        let msg_expiry_dur = self.msg_expiry_dur;
        for part in parts {
            self.send_routing_message_with_expiry(
                src,
                dst,
                part,
                Some(Instant::now() + msg_expiry_dur),
            )?;
            self.stats.increase_user_msg_part();
        }
        Ok(())
    }
}

impl Base for Client {
    fn crust_service(&self) -> &Service {
        &self.crust_service
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

    fn handle_lost_peer(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        debug!("{:?} Received LostPeer - {:?}", self, pub_id);

        if self.proxy_pub_id == pub_id {
            debug!("{:?} Lost bootstrap connection to {}.", self, pub_id);
            outbox.send_event(Event::Terminate);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn stats(&mut self) -> &mut Stats {
        &mut self.stats
    }

    fn min_section_size(&self) -> usize {
        self.min_section_size
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
                "{:?} Timed out waiting for {:?}: {:?}",
                self,
                ack,
                unacked_msg
            );

            let msg_expired = unacked_msg.expires_at.map_or(false, |i| i < Instant::now());
            if msg_expired || unacked_msg.route as usize == self.min_section_size {
                debug!(
                    "{:?} Message unable to be acknowledged - giving up. {:?}",
                    self,
                    unacked_msg
                );
                self.stats.count_unacked();
            } else if let Err(error) = self.send_routing_message_via_route(
                unacked_msg.routing_msg,
                unacked_msg.route,
                unacked_msg.expires_at,
            )
            {
                debug!("{:?} Failed to send message: {:?}", self, error);
            }
            // Resend a msg part on ack time out doesn't count in stats.
        }
    }

    fn send_routing_message_via_route(
        &mut self,
        routing_msg: RoutingMessage,
        route: u8,
        expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        self.stats.count_route(route);

        if routing_msg.dst.is_client() && self.in_authority(&routing_msg.dst) {
            return Ok(()); // Message is for us.
        }

        // Get PublicId of the proxy node
        match routing_msg.src {
            Authority::Client { ref proxy_node_name, .. } => {
                if *self.proxy_pub_id.name() != *proxy_node_name {
                    error!(
                        "{:?} Unable to find connection to proxy node in proxy map",
                        self
                    );
                    return Err(RoutingError::ProxyConnectionNotFound);
                }
            }
            _ => {
                error!(
                    "{:?} Source should be client if our state is a Client",
                    self
                );
                return Err(RoutingError::InvalidSource);
            }
        };

        let signed_msg = SignedMessage::new(routing_msg, self.full_id(), vec![])?;

        let proxy_pub_id = self.proxy_pub_id;
        if self.add_to_pending_acks(signed_msg.routing_message(), route, expires_at) &&
            !self.filter_outgoing_routing_msg(signed_msg.routing_message(), &proxy_pub_id, route)
        {
            let bytes = self.to_hop_bytes(
                signed_msg.clone(),
                route,
                BTreeSet::new(),
            )?;
            self.send_or_drop(&proxy_pub_id, bytes, signed_msg.priority());
        }

        Ok(())
    }

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

#[cfg(feature = "use-mock-crust")]
impl Client {
    pub fn get_timed_out_tokens(&mut self) -> Vec<u64> {
        self.timer.get_timed_out_tokens()
    }

    pub fn get_user_msg_parts_count(&self) -> u64 {
        self.stats.msg_user_parts
    }
}

impl Debug for Client {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Client({})", self.name())
    }
}
