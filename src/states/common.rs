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
use maidsafe_utilities::serialisation;
use std::sync::mpsc::Sender;

use authority::Authority;
use error::RoutingError;
use event::Event;
use id::FullId;
use messages::{HopMessage, Message, SignedMessage, UserMessage};
use stats::Stats;
use xor_name::XorName;

pub const USER_MSG_CACHE_EXPIRY_DURATION_SECS: u64 = 60 * 20;

pub fn handle_user_message(msg: UserMessage,
                           src: Authority,
                           dst: Authority,
                           event_sender: &Sender<Event>,
                           stats: &mut Stats)
{
    let event = match msg {
        UserMessage::Request(request) => {
            stats.count_request(&request);
            Event::Request {
                request: request,
                src: src,
                dst: dst,
            }
        }
        UserMessage::Response(response) => {
            stats.count_response(&response);
            Event::Response {
                response: response,
                src: src,
                dst: dst,
            }
        }
    };

    let _ = event_sender.send(event);
}

pub fn to_hop_bytes(signed_msg: SignedMessage,
                    route: u8,
                    sent_to: Vec<XorName>,
                    full_id: &FullId)
                    -> Result<Vec<u8>, RoutingError> {
    let hop_msg = try!(HopMessage::new(signed_msg,
                                       route,
                                       sent_to,
                                       full_id.signing_private_key()));
    let message = Message::Hop(hop_msg);
    Ok(try!(serialisation::serialise(&message)))
}

pub fn to_tunnel_hop_bytes(signed_msg: SignedMessage,
                           route: u8,
                           sent_to: Vec<XorName>,
                           src: PeerId,
                           dst: PeerId,
                           full_id: &FullId)
                           -> Result<Vec<u8>, RoutingError> {
    let hop_msg = try!(HopMessage::new(signed_msg.clone(),
                                       route,
                                       sent_to,
                                       full_id.signing_private_key()));
    let message = Message::TunnelHop {
        content: hop_msg,
        src: src,
        dst: dst,
    };
    Ok(try!(serialisation::serialise(&message)))
}
