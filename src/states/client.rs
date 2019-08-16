// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::common::{proxied, Base, Bootstrapped, BootstrappedNotEstablished};
use crate::{
    error::{InterfaceError, RoutingError},
    event::Event,
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, MessageContent, Request, RoutingMessage, UserMessage},
    outbox::EventBox,
    peer_map::PeerMap,
    routing_message_filter::RoutingMessageFilter,
    routing_table::Authority,
    state_machine::Transition,
    time::{Duration, Instant},
    timer::Timer,
    xor_name::XorName,
    NetworkService,
};
use std::fmt::{self, Display, Formatter};

pub struct ClientDetails {
    pub network_service: NetworkService,
    pub full_id: FullId,
    pub min_section_size: usize,
    pub msg_expiry_dur: Duration,
    pub peer_map: PeerMap,
    pub proxy_pub_id: PublicId,
    pub timer: Timer,
}

/// A node connecting a user to the network, as opposed to a routing / data storage node.
///
/// Each client has a _proxy_: a node through which all requests are routed.
pub struct Client {
    network_service: NetworkService,
    full_id: FullId,
    min_section_size: usize,
    peer_map: PeerMap,
    proxy_pub_id: PublicId,
    routing_msg_filter: RoutingMessageFilter,
    timer: Timer,
    msg_expiry_dur: Duration,
}

impl Client {
    pub fn from_bootstrapping(details: ClientDetails, outbox: &mut dyn EventBox) -> Self {
        let client = Client {
            network_service: details.network_service,
            full_id: details.full_id,
            min_section_size: details.min_section_size,
            peer_map: details.peer_map,
            proxy_pub_id: details.proxy_pub_id,
            routing_msg_filter: RoutingMessageFilter::new(),
            timer: details.timer,
            msg_expiry_dur: details.msg_expiry_dur,
        };

        debug!("{} State changed to Client.", client);

        outbox.send_event(Event::Connected);
        client
    }

    fn dispatch_routing_message(
        &mut self,
        routing_msg: RoutingMessage,
        outbox: &mut dyn EventBox,
    ) -> Transition {
        match routing_msg.content {
            MessageContent::UserMessage { content, .. } => {
                trace!(
                    "{} Got UserMessage {} from {:?} to {:?}.",
                    self,
                    content.short_display(),
                    routing_msg.src,
                    routing_msg.dst
                );
                outbox.send_event(content.into_event(routing_msg.src, routing_msg.dst));
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
        content: UserMessage,
        priority: u8,
    ) -> Result<(), RoutingError> {
        let msg_expiry_dur = self.msg_expiry_dur;
        self.send_routing_message_with_expiry(
            src,
            dst,
            MessageContent::UserMessage { content, priority },
            Some(Instant::now() + msg_expiry_dur),
        )
    }
}

impl Base for Client {
    fn network_service(&self) -> &NetworkService {
        &self.network_service
    }

    fn network_service_mut(&mut self) -> &mut NetworkService {
        &mut self.network_service
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

    fn min_section_size(&self) -> usize {
        self.min_section_size
    }

    fn peer_map(&self) -> &PeerMap {
        &self.peer_map
    }

    fn peer_map_mut(&mut self) -> &mut PeerMap {
        &mut self.peer_map
    }

    fn handle_client_send_request(
        &mut self,
        dst: Authority<XorName>,
        content: Request,
        priority: u8,
    ) -> Result<(), InterfaceError> {
        let src = Authority::Client {
            client_id: *self.full_id.public_id(),
            proxy_node_name: *self.proxy_pub_id.name(),
        };
        let user_msg = UserMessage::Request(content);

        match self.send_user_message(src, dst, user_msg, priority) {
            Err(RoutingError::Interface(err)) => Err(err),
            Err(_) | Ok(_) => Ok(()),
        }
    }

    fn handle_timeout(&mut self, _token: u64, _: &mut dyn EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_peer_lost(&mut self, pub_id: PublicId, outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - Lost peer {:?}", self, pub_id);

        if self.proxy_pub_id == pub_id {
            debug!("{} - Lost bootstrap connection to {}.", self, pub_id);
            outbox.send_event(Event::Terminated);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        _: PublicId,
        _: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        debug!("{} Unhandled direct message: {:?}", self, msg);
        Ok(Transition::Stay)
    }

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        if let Some(routing_msg) = self.filter_hop_message(msg)? {
            Ok(self.dispatch_routing_message(routing_msg, outbox))
        } else {
            Ok(Transition::Stay)
        }
    }
}

impl Bootstrapped for Client {
    fn send_routing_message_impl(
        &mut self,
        routing_msg: RoutingMessage,
        expires_at: Option<Instant>,
    ) -> Result<(), RoutingError> {
        self.send_routing_message_via_proxy(routing_msg, expires_at)
    }

    fn routing_msg_filter(&mut self) -> &mut RoutingMessageFilter {
        &mut self.routing_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl BootstrappedNotEstablished for Client {
    fn get_proxy_public_id(&self, proxy_name: &XorName) -> Result<&PublicId, RoutingError> {
        proxied::get_proxy_public_id(self, &self.proxy_pub_id, proxy_name)
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
