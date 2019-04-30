// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::common::{unrelocated, Base, Bootstrapped, Unapproved, USER_MSG_CACHE_EXPIRY_DURATION};
use crate::ack_manager::{Ack, AckManager, UnacknowledgedMessage};
use crate::action::Action;
use crate::chain::SectionInfo;
use crate::error::{InterfaceError, Result, RoutingError};
use crate::event::Event;
use crate::id::{FullId, PublicId};
use crate::messages::{
    DirectMessage, HopMessage, Message, MessageContent, RoutingMessage, UserMessage,
    UserMessageCache,
};
use crate::outbox::EventBox;
use crate::routing_message_filter::RoutingMessageFilter;
use crate::routing_table::Authority;
use crate::state_machine::Transition;
use crate::states::common::from_crust_bytes;
use crate::time::{Duration, Instant};
use crate::timer::Timer;
use crate::xor_name::XorName;
use crate::CrustBytes;
use crate::{CrustEvent, Service};
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

/// Duration to wait before sending rate limit exceeded messages.
pub const RATE_EXCEED_RETRY: Duration = Duration::from_millis(800);

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
    timer: Timer,
    user_msg_cache: UserMessageCache,
    resend_buf: BTreeMap<u64, UnacknowledgedMessage>,
    msg_expiry_dur: Duration,
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub fn from_bootstrapping(
        crust_service: Service,
        full_id: FullId,
        min_section_size: usize,
        proxy_pub_id: PublicId,
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
            timer: timer,
            user_msg_cache: UserMessageCache::with_expiry_duration(USER_MSG_CACHE_EXPIRY_DURATION),
            resend_buf: Default::default(),
            msg_expiry_dur: msg_expiry_dur,
        };

        debug!("{} State changed to Client.", client);

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
            Action::GetId { result_tx } => {
                let _ = result_tx.send(*self.id());
            }
            Action::HandleTimeout(token) => self.handle_timeout(token),
            Action::TakeResourceProofResult(..) => {
                error!("Action::TakeResourceProofResult received by Client state");
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
                debug!("{} Unhandled crust event {:?}", self, crust_event);
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
                unacked_msg.src_section,
                unacked_msg.route,
                unacked_msg.expires_at,
            ) {
                debug!("{} Failed to send message: {:?}", self, error);
            }
            return;
        }

        // Check if token corresponds to an unacknowledged msg.
        self.resend_unacknowledged_timed_out_msgs(token)
    }

    fn handle_new_message(
        &mut self,
        pub_id: PublicId,
        bytes: CrustBytes,
        outbox: &mut EventBox,
    ) -> Transition {
        let transition = match from_crust_bytes(bytes) {
            Ok(Message::Hop(hop_msg)) => self.handle_hop_message(hop_msg, pub_id, outbox),
            Ok(Message::Direct(direct_msg)) => self.handle_direct_message(direct_msg),
            Err(error) => Err(error),
        };

        match transition {
            Ok(transition) => transition,
            Err(RoutingError::FilterCheckFailed) => Transition::Stay,
            Err(error) => {
                debug!("{} {:?}", self, error);
                Transition::Stay
            }
        }
    }

    fn handle_hop_message(
        &mut self,
        hop_msg: HopMessage,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition> {
        if self.proxy_pub_id != pub_id {
            return Err(RoutingError::UnknownConnection(pub_id));
        }

        if let Some(routing_msg) = self.filter_hop_message(hop_msg, pub_id)? {
            Ok(self.dispatch_routing_message(routing_msg, outbox))
        } else {
            Ok(Transition::Stay)
        }
    }

    fn handle_direct_message(&mut self, direct_msg: DirectMessage) -> Result<Transition> {
        if let DirectMessage::ProxyRateLimitExceeded { ack } = direct_msg {
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
            debug!("{} Unhandled direct message: {:?}", self, direct_msg);
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
    ) -> Result<()> {
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
        debug!("{} Received LostPeer - {:?}", self, pub_id);

        if self.proxy_pub_id == pub_id {
            debug!("{} Lost bootstrap connection to {}.", self, pub_id);
            outbox.send_event(Event::Terminated);
            Transition::Terminate
        } else {
            Transition::Stay
        }
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

impl Unapproved for Client {
    const SEND_ACK: bool = false;

    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId> {
        unrelocated::get_proxy_public_id(self, &self.proxy_pub_id, proxy_name)
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
