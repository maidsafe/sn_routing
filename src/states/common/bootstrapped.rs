// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use ack_manager::{ACK_TIMEOUT_SECS, Ack, AckManager, UnacknowledgedMessage};
use authority::Authority;
use crust::PeerId;
use error::RoutingError;
use maidsafe_utilities::serialisation;
use messages::{HopMessage, Message, MessageContent, RoutingMessage, SignedMessage};
use peer_manager::MIN_GROUP_SIZE;
use signed_message_filter::SignedMessageFilter;
use std::time::Duration;
use super::Base;
use timer::Timer;
use xor_name::XorName;

// Common functionality for states that are bootstrapped (have established a crust
// connection to at least one peer).
pub trait Bootstrapped: Base {
    fn ack_mgr(&self) -> &AckManager;
    fn ack_mgr_mut(&mut self) -> &mut AckManager;

    fn send_routing_message_via_route(&mut self,
                                      routing_msg: RoutingMessage,
                                      route: u8)
                                      -> Result<(), RoutingError>;

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
            debug!("{:?} - Ejected pending ack: {:?} - {:?}",
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

            if unacked_msg.route as usize == MIN_GROUP_SIZE {
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

    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        self.send_routing_message_via_route(routing_msg, 0)
    }

    fn send_ack(&mut self, routing_msg: &RoutingMessage, route: u8) {
        self.send_ack_from(routing_msg, route, routing_msg.dst);
    }

    fn send_ack_from(&mut self, routing_msg: &RoutingMessage, route: u8, src: Authority) {
        if let MessageContent::Ack(..) = routing_msg.content {
            return;
        }

        let response = match RoutingMessage::ack_from(routing_msg, src) {
            Ok(response) => response,
            Err(error) => {
                error!("{:?} - Failed to create ack: {:?}", self, error);
                return;
            }
        };

        if let Err(error) = self.send_routing_message_via_route(response, route) {
            error!("{:?} - Failed to send ack: {:?}", self, error);
        }
    }

    // Serialise HopMessage containing the given signed message.
    fn to_hop_bytes(&self,
                    signed_msg: SignedMessage,
                    route: u8,
                    sent_to: Vec<XorName>)
                    -> Result<Vec<u8>, RoutingError> {
        let hop_msg = try!(HopMessage::new(signed_msg,
                                           route,
                                           sent_to,
                                           self.full_id().signing_private_key()));
        let message = Message::Hop(hop_msg);
        Ok(try!(serialisation::serialise(&message)))
    }
}
