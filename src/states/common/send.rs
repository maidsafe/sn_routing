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
use std::fmt::Debug;

use authority::Authority;
use error::RoutingError;
use messages::{DirectMessage, Message, MessageContent, RoutingMessage};
use super::{HandleLostPeer, StateCommon};

pub trait SendDirectMessage: SendOrDrop + StateCommon {
    fn wrap_direct_message(&self,
                           dst_id: &PeerId,
                           direct_message: DirectMessage)
                           -> (Message, PeerId) {
        (Message::Direct(direct_message), *dst_id)
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
}

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
            error!("{:?} - Failed to send ack: {:?}", self, error);
        }
    }
}

pub trait SendOrDrop {
    /// Sends the given `bytes` to the peer with the given Crust `PeerId`. If that results in an
    /// error, it disconnects from the peer.
    fn send_or_drop(&mut self,
                    peer_id: &PeerId,
                    bytes: Vec<u8>,
                    priority: u8)
                    -> Result<(), RoutingError>;
}

// ----- Default trait implementations -----------------------------------------

impl<T> SendOrDrop for T
    where T: StateCommon + HandleLostPeer
{
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
}
