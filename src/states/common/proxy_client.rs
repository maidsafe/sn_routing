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

use authority::Authority;
use error::RoutingError;
use event::Event;
use id::PublicId;
use messages::{HopMessage, RoutingMessage, SignedMessage};
use peer_manager::GROUP_SIZE;
use state_machine::Transition;
use super::{Bootstrapped, DispatchRoutingMessage, HandleHopMessage, HandleLostPeer, SendOrDrop,
            SendRoutingMessage};

// Marker trait for states that connect via proxy node.
pub trait ProxyClient {}

impl<T> HandleHopMessage for T
    where T: Bootstrapped + DispatchRoutingMessage + ProxyClient + SendRoutingMessage
{
    fn handle_hop_message(&mut self,
                          hop_msg: HopMessage,
                          peer_id: PeerId)
                          -> Result<Transition, RoutingError> {
        if let Some(pub_id) = self.peer_mgr().get_proxy_public_id(&peer_id) {
            try!(hop_msg.verify(pub_id.signing_public_key()));
        } else {
            return Err(RoutingError::UnknownConnection(peer_id));
        }

        let signed_msg = hop_msg.content();
        try!(signed_msg.check_integrity());

        // Prevents someone sending messages repeatedly to us
        if self.signed_msg_filter().filter_incoming(signed_msg) > GROUP_SIZE {
            return Err(RoutingError::FilterCheckFailed);
        }

        let routing_msg = signed_msg.routing_message();

        if !is_recipient(self.full_id().public_id(), &routing_msg.dst) {
            return Ok(Transition::Stay);
        }

        if let Some(msg) = try!(self.accumulate(routing_msg, signed_msg.public_id())) {
            if msg.src.is_group() {
                self.send_ack(&msg, 0);
            }

            self.dispatch_routing_message(msg)
        } else {
            Ok(Transition::Stay)
        }
    }
}

impl<T> HandleLostPeer for T
    where T: Bootstrapped + ProxyClient
{
    fn handle_lost_peer(&mut self, peer_id: PeerId) -> Transition {
        if peer_id == self.crust_service().id() {
            error!("{:?} LostPeer fired with our crust peer id", self);
            return Transition::Stay;
        }

        debug!("{:?} Received LostPeer - {:?}", self, peer_id);
        let _ = self.peer_mgr_mut().remove_peer(&peer_id);

        if self.peer_mgr().get_proxy_public_id(&peer_id).is_some() {
            if let Some((_, _, public_id)) = self.peer_mgr_mut().remove_proxy() {
                debug!("{:?} Lost bootstrap connection to {:?} ({:?}).",
                       self,
                       public_id.name(),
                       peer_id);
                self.send_event(Event::Terminate);
                return Transition::Terminate;
            }
        }

        Transition::Stay
    }
}

impl<T> SendRoutingMessage for T
    where T: Bootstrapped + ProxyClient + SendOrDrop
{
    fn send_routing_message_via_route(&mut self,
                                      routing_msg: RoutingMessage,
                                      route: u8)
                                      -> Result<(), RoutingError> {
        self.stats().count_route(route);

        if let Authority::Client { .. } = routing_msg.dst {
            if is_recipient(self.full_id().public_id(), &routing_msg.dst) {
                return Ok(()); // Message is for us.
            }
        }

        // Get PeerId of the proxy node
        let peer_id = if let Authority::Client { ref proxy_node_name, .. } = routing_msg.src {
            if let Some(&peer_id) = self.peer_mgr().get_proxy_peer_id(proxy_node_name) {
                peer_id
            } else {
                error!("{:?} - Unable to find connection to proxy node in proxy map",
                       self);
                return Err(RoutingError::ProxyConnectionNotFound);
            }
        } else {
            error!("{:?} - Source should be client if our state is a Client",
                   self);
            return Err(RoutingError::InvalidSource);
        };

        let signed_msg = try!(SignedMessage::new(routing_msg, &self.full_id()));

        if !self.add_to_pending_acks(&signed_msg, route) {
            return Ok(());
        }

        let (peer_id, bytes) = if self.crust_service().is_connected(&peer_id) {
            let bytes =
                try!(super::to_hop_bytes(signed_msg.clone(), route, Vec::new(), &self.full_id()));
            (peer_id, bytes)
        } else {
            trace!("{:?} - Not connected to {:?}. Dropping peer.",
                   self,
                   peer_id);
            super::disconnect_peer(self, self.crust_service(), self.peer_mgr(), &peer_id);
            return Ok(());
        };

        if !self.filter_outgoing_signed_msg(&signed_msg, &peer_id, route) {
            if let Err(error) = self.send_or_drop(&peer_id, bytes, signed_msg.priority()) {
                info!("{:?} - Error sending message to {:?}: {:?}.",
                      self,
                      peer_id,
                      error);
            }
        }

        Ok(())
    }
}

fn is_recipient(public_id: &PublicId, dst: &Authority) -> bool {
    if let Authority::Client { ref client_key, .. } = *dst {
        client_key == public_id.signing_public_key()
    } else {
        false
    }
}
