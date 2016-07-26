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

mod bootstrapped;
mod connect;
mod proxy_client;

use crust::{PeerId, Service};
use maidsafe_utilities::serialisation;
use sodiumoxide::crypto::sign;
use std::fmt::Debug;

use authority::Authority;
use error::RoutingError;
use event::Event;
use id::{FullId, PublicId};
use messages::{DirectMessage, HopMessage, Message, MessageContent, RoutingMessage, SignedMessage,
               UserMessage};
use state_machine::Transition;
use stats::Stats;
use xor_name::XorName;

pub use self::bootstrapped::Bootstrapped;
pub use self::connect::Connect;
pub use self::proxy_client::ProxyClient;

pub const USER_MSG_CACHE_EXPIRY_DURATION_SECS: u64 = 60 * 20;

// Serialise HopMessage containing the given signed message.
pub fn to_hop_bytes(signed_msg: SignedMessage,
                    route: u8,
                    sent_to: Vec<XorName>,
                    full_id: &FullId)
                    -> Result<Vec<u8>, RoutingError> {
    let hop_msg = try!(HopMessage::new(signed_msg, route, sent_to, full_id.signing_private_key()));
    let message = Message::Hop(hop_msg);
    Ok(try!(serialisation::serialise(&message)))
}

// Verify the serialised public id against the signature.
pub fn verify_signed_public_id(serialised_public_id: &[u8],
                               signature: &sign::Signature)
                               -> Result<PublicId, RoutingError> {
    let public_id: PublicId = try!(serialisation::deserialise(serialised_public_id));
    let public_key = public_id.signing_public_key();
    if sign::verify_detached(signature, serialised_public_id, public_key) {
        Ok(public_id)
    } else {
        Err(RoutingError::FailedSignature)
    }
}

// Trait for all states.
pub trait AnyState: Debug {
    fn crust_service(&self) -> &Service;
    fn full_id(&self) -> &FullId;
    fn stats(&mut self) -> &mut Stats;
    fn send_event(&self, event: Event);

    fn handle_lost_peer(&mut self, _peer_id: PeerId) -> Transition {
        Transition::Stay
    }

    fn name(&self) -> &XorName {
        self.full_id().public_id().name()
    }

    fn send_direct_message(&mut self,
                           dst_id: &PeerId,
                           direct_message: DirectMessage)
                           -> Result<(), RoutingError> {
        self.stats().count_direct_message(&direct_message);

        let priority = direct_message.priority();
        let (message, peer_id) = self.wrap_direct_message(dst_id, direct_message);

        let raw_bytes = match serialisation::serialise(&message) {
            Err(error) => {
                error!("{:?} Failed to serialise message {:?}: {:?}",
                       self,
                       message,
                       error);
                return Err(error.into());
            }
            Ok(bytes) => bytes,
        };

        self.send_or_drop(&peer_id, raw_bytes, priority)
    }

    // Sends the given `bytes` to the peer with the given Crust `PeerId`. If that results in an
    // error, it disconnects from the peer.
    fn send_or_drop(&mut self,
                    peer_id: &PeerId,
                    bytes: Vec<u8>,
                    priority: u8)
                    -> Result<(), RoutingError> {
        self.stats().count_bytes(bytes.len());

        if let Err(err) = self.crust_service().send(*peer_id, bytes.clone(), priority) {
            info!("{:?} Connection to {:?} failed. Calling crust::Service::disconnect.",
                  self,
                  peer_id);
            self.crust_service().disconnect(*peer_id);
            let _ = self.handle_lost_peer(*peer_id);
            return Err(err.into());
        }

        Ok(())
    }

    // Wraps the given `DirectMessage` into `Message`.
    fn wrap_direct_message(&self,
                           dst_id: &PeerId,
                           direct_message: DirectMessage)
                           -> (Message, PeerId) {
        (Message::Direct(direct_message), *dst_id)
    }
}

// Trait for handling received hop messages.
pub trait HandleHopMessage {
    fn handle_hop_message(&mut self,
                          hop_msg: HopMessage,
                          peer_id: PeerId)
                          -> Result<Transition, RoutingError>;
}

// Trait for handling received user messages.
pub trait HandleUserMessage: AnyState {
    // Implement this method to add the given user message part to the user
    // message cache, and returning the complete user message if it has all the
    // parts, or None otherwise.
    fn add_to_user_msg_cache(&mut self,
                             hash: u64,
                             part_count: u32,
                             part_index: u32,
                             payload: Vec<u8>)
                             -> Option<UserMessage>;

    fn handle_user_message_part(&mut self,
                                hash: u64,
                                part_count: u32,
                                part_index: u32,
                                payload: Vec<u8>,
                                src: Authority,
                                dst: Authority) {
        if let Some(msg) = self.add_to_user_msg_cache(hash, part_count, part_index, payload) {
            self.handle_user_message(msg, src, dst)
        }
    }

    fn handle_user_message(&mut self, msg: UserMessage, src: Authority, dst: Authority) {
        let event = match msg {
            UserMessage::Request(request) => {
                self.stats().count_request(&request);
                Event::Request {
                    request: request,
                    src: src,
                    dst: dst,
                }
            }
            UserMessage::Response(response) => {
                self.stats().count_response(&response);
                Event::Response {
                    response: response,
                    src: src,
                    dst: dst,
                }
            }
        };

        self.send_event(event);
    }
}

// Trait for states that need to send routing messages.
pub trait SendRoutingMessage: Debug {
    fn send_routing_message_via_route(&mut self,
                                      routing_msg: RoutingMessage,
                                      route: u8)
                                      -> Result<(), RoutingError>;

    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError> {
        self.send_routing_message_via_route(routing_msg, 0)
    }

    fn send_ack(&mut self, routing_msg: &RoutingMessage, route: u8) {
        self.send_ack_from(routing_msg, route, routing_msg.dst.clone());
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
            debug!("{:?} - Failed to send ack: {:?}", self, error);
        }
    }
}

// Trait to provide test-only details from states.
#[cfg(feature = "use-mock-crust")]
pub trait Testable: Bootstrapped {
    /// Clears all state containers.
    fn clear_state(&mut self) {}

    /// Resends all unacknowledged messages.
    fn resend_unacknowledged(&mut self) -> bool {
        self.timer().stop();
        let timer_tokens = self.ack_mgr().timer_tokens();
        for timer_token in &timer_tokens {
            self.resend_unacknowledged_timed_out_msgs(*timer_token);
        }
        !timer_tokens.is_empty()
    }

    /// Are there any unacknowledged messages?
    fn has_unacknowledged(&self) -> bool {
        self.ack_mgr().has_pending()
    }
}
