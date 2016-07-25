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
mod send;

use crust::{PeerId, Service};
use maidsafe_utilities::serialisation;
use sodiumoxide::crypto::sign;
use std::fmt::Debug;

use authority::Authority;
use error::RoutingError;
use event::Event;
use id::{FullId, PublicId};
use messages::{HopMessage, Message, RoutingMessage, SignedMessage, UserMessage};
use peer_manager::PeerManager;
use state_machine::Transition;
use stats::Stats;
use xor_name::XorName;

pub use self::bootstrapped::Bootstrapped;
pub use self::connect::Connect;
pub use self::proxy_client::ProxyClient;
pub use self::send::{SendDirectMessage, SendOrDrop, SendRoutingMessage};

pub const USER_MSG_CACHE_EXPIRY_DURATION_SECS: u64 = 60 * 20;

// Serialize HopMessage containing the given signed message.
pub fn to_hop_bytes(signed_msg: SignedMessage,
                    route: u8,
                    sent_to: Vec<XorName>,
                    full_id: &FullId)
                    -> Result<Vec<u8>, RoutingError> {
    let hop_msg = try!(HopMessage::new(signed_msg, route, sent_to, full_id.signing_private_key()));
    let message = Message::Hop(hop_msg);
    Ok(try!(serialisation::serialise(&message)))
}

// Verify the serialized public id against the signature.
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
pub trait StateCommon: Debug {
    fn crust_service(&self) -> &Service;
    fn full_id(&self) -> &FullId;
    fn stats(&mut self) -> &mut Stats;
    fn send_event(&self, event: Event);

    fn name(&self) -> &XorName {
        self.full_id().public_id().name()
    }
}

// Trait for states that handle routing messages.
pub trait DispatchRoutingMessage {
    fn dispatch_routing_message(&mut self,
                                routing_msg: RoutingMessage)
                                -> Result<Transition, RoutingError>;
}

// Trait for states that have PeerManager.
pub trait GetPeerManager {
    fn peer_mgr(&self) -> &PeerManager;
    fn peer_mgr_mut(&mut self) -> &mut PeerManager;
}

// Trait for handling lost peers.
pub trait HandleLostPeer {
    fn handle_lost_peer(&mut self, peer_id: PeerId) -> Transition;
}

// Trait for handling received hop messages.
pub trait HandleHopMessage {
    fn handle_hop_message(&mut self,
                          hop_msg: HopMessage,
                          peer_id: PeerId)
                          -> Result<Transition, RoutingError>;
}

// Trait for handling received user messages.
pub trait HandleUserMessage: StateCommon {
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
