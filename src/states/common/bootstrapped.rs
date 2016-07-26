// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use crust::PeerId;
use std::time::Duration;

use ack_manager::{ACK_TIMEOUT_SECS, Ack, AckManager, UnacknowledgedMessage};
use error::RoutingError;
use id::PublicId;
use messages::{MessageContent, RoutingMessage, SignedMessage};
use peer_manager::GROUP_SIZE;
use signed_message_filter::SignedMessageFilter;
use state_machine::Transition;
use super::{AnyState, SendRoutingMessage};
use timer::Timer;

// Common functionality for states that are bootstrapped (have established a crust
// connection to at least one peer).
pub trait Bootstrapped: AnyState + SendRoutingMessage {
    fn accumulate(&mut self,
                  routing_msg: &RoutingMessage,
                  public_id: &PublicId)
                  -> Result<Option<RoutingMessage>, RoutingError>;

    fn ack_mgr(&self) -> &AckManager;
    fn ack_mgr_mut(&mut self) -> &mut AckManager;

    fn dispatch_routing_message(&mut self,
                                routing_msg: RoutingMessage)
                                -> Result<Transition, RoutingError>;

    fn signed_msg_filter(&mut self) -> &mut SignedMessageFilter;
    fn timer(&mut self) -> &mut Timer;

    fn add_to_pending_acks(&mut self, signed_msg: &SignedMessage, route: u8) -> bool {
        // If this is not an ack and we're the source, expect to receive an ack for this.
        if let MessageContent::Ack(..) = signed_msg.routing_message().content {
            return true;
        }

        if *signed_msg.public_id() != *self.full_id().public_id() {
            return true;
        }

        let ack = match Ack::compute(signed_msg.routing_message()) {
            Ok(ack) => ack,
            Err(error) => {
                error!("Failed to create ack: {:?}", error);
                return true;
            }
        };

        if self.ack_mgr_mut().did_receive(ack) {
            return false;
        }

        let token = self.timer().schedule(Duration::from_secs(ACK_TIMEOUT_SECS));
        let unacked_msg = UnacknowledgedMessage {
            routing_msg: signed_msg.routing_message().clone(),
            route: route,
            timer_token: token,
        };

        if let Some(ejected) = self.ack_mgr_mut().add_to_pending(ack, unacked_msg) {
            // FIXME: This currently occurs for Connect request and
            // GetNodeName response. Connect requests arent filtered which
            // should get resolved with peer_mgr completion.
            // GetNodeName response resends from a node needs to get looked into.
            trace!("{:?} - Ejected pending ack: {:?} - {:?}",
                   self,
                   ack,
                   ejected);
        }

        true
    }

    /// Adds the outgoing signed message to the statistics and returns `true`
    /// if it should be blocked due to deduplication.
    fn filter_outgoing_signed_msg(&mut self,
                                  msg: &SignedMessage,
                                  peer_id: &PeerId,
                                  route: u8)
                                  -> bool {
        if self.signed_msg_filter().filter_outgoing(msg, peer_id, route) {
            return true;
        }

        self.stats().count_routing_message(msg.routing_message());
        false
    }

    fn resend_unacknowledged_timed_out_msgs(&mut self, token: u64) {
        if let Some((unacked_msg, ack)) = self.ack_mgr_mut().find_timed_out(token) {
            trace!("{:?} - Timed out waiting for ack({}) {:?}",
                   self,
                   ack,
                   unacked_msg);

            if unacked_msg.route as usize == GROUP_SIZE {
                debug!("{:?} - Message unable to be acknowledged - giving up. {:?}",
                       self,
                       unacked_msg);
                self.stats().count_unacked();
            } else if let Err(error) =
                   self.send_routing_message_via_route(unacked_msg.routing_msg, unacked_msg.route) {
                debug!("{:?} Failed to send message: {:?}", self, error);
            }
        }
    }
}
