// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Base;
use crate::{
    ack_manager::{Ack, AckManager, UnacknowledgedMessage, ACK_TIMEOUT},
    error::Result,
    id::PublicId,
    messages::{MessageContent, RoutingMessage},
    routing_message_filter::RoutingMessageFilter,
    routing_table::Authority,
    time::Instant,
    timer::Timer,
    xor_name::XorName,
};

// Common functionality for states that are bootstrapped (have established a network
// connection to at least one peer).
pub trait Bootstrapped: Base {
    fn ack_mgr(&self) -> &AckManager;
    fn ack_mgr_mut(&mut self) -> &mut AckManager;

    fn send_routing_message_impl(
        &mut self,
        routing_msg: RoutingMessage,
        expires_at: Option<Instant>,
    ) -> Result<()>;

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter;
    fn timer(&mut self) -> &mut Timer;

    /// Examines a message, and possibly adds a pending ack. Returns true unless
    /// this is a message we already received an ack for.
    ///
    /// This short-circuits when the message is an ack or is not from us; in
    /// these cases no ack is expected and the function returns true.
    fn add_to_pending_acks(
        &mut self,
        routing_msg: &RoutingMessage,
        route: u8,
        expires_at: Option<Instant>,
    ) -> bool {
        // If this is not an ack and we're the source, expect to receive an ack for this.
        if let MessageContent::Ack(..) = routing_msg.content {
            return true;
        }

        let ack = match Ack::compute(routing_msg) {
            Ok(ack) => ack,
            Err(error) => {
                error!("{} Failed to create ack: {:?}", self, error);
                return true;
            }
        };

        if self.ack_mgr_mut().did_receive(ack) {
            return false;
        }

        let token = self.timer().schedule(ACK_TIMEOUT);
        let unacked_msg = UnacknowledgedMessage {
            routing_msg: routing_msg.clone(),
            route,
            timer_token: token,
            expires_at,
        };

        if let Some(ejected) = self.ack_mgr_mut().add_to_pending(ack, unacked_msg) {
            debug!("{} - Ejected pending ack: {:?} - {:?}", self, ack, ejected);
        }

        true
    }

    /// Adds the outgoing signed message to the statistics and returns `true`
    /// if it should be blocked due to deduplication.
    fn filter_outgoing_routing_msg(
        &mut self,
        msg: &RoutingMessage,
        pub_id: &PublicId,
        route: u8,
    ) -> bool {
        self.routing_msg_filter()
            .filter_outgoing(msg, pub_id, route)
    }

    fn resend_unacknowledged_timed_out_msgs(&mut self, token: u64) {
        if let Some((unacked_msg, _ack)) = self.ack_mgr_mut().find_timed_out(token) {
            if unacked_msg.route as usize == self.min_section_size() {
                debug!(
                    "{} Message unable to be acknowledged - giving up. {:?}",
                    self, unacked_msg
                );
            } else if let Err(error) =
                self.send_routing_message_impl(unacked_msg.routing_msg, unacked_msg.expires_at)
            {
                debug!("{} Failed to send message: {:?}", self, error);
            }
        }
    }

    fn send_routing_message_with_expiry(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: MessageContent,
        expires_at: Option<Instant>,
    ) -> Result<()> {
        let routing_msg = RoutingMessage {
            src: src,
            dst: dst,
            content: content,
        };
        self.send_routing_message_impl(routing_msg, expires_at)
    }

    fn send_routing_message(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: MessageContent,
    ) -> Result<()> {
        self.send_routing_message_with_expiry(src, dst, content, None)
    }
}
