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

use crust::{PeerId, Service};
use crust::Event as CrustEvent;
use lru_time_cache::LruCache;
use maidsafe_utilities::{self, serialisation};
use std::fmt::{self, Debug, Formatter};
use std::sync::mpsc::Sender;
use std::time::Duration;

use ack_manager::{ACK_TIMEOUT_SECS, AckManager};
use action::Action;
use authority::Authority;
use error::{InterfaceError, RoutingError};
use event::Event;
use id::{FullId, PublicId};
use message_accumulator::MessageAccumulator;
use messages::{Message, MessageContent, RoutingMessage, UserMessage, UserMessageCache};
use peer_manager::{GROUP_SIZE, PeerManager};
use signed_message_filter::SignedMessageFilter;
use state_machine::Transition;
use stats::Stats;
use super::common::{self, Bootstrapped, DispatchRoutingMessage, HandleHopMessage, HandleLostPeer,
                    HandleUserMessage, ProxyClient, SendRoutingMessage, StateCommon,
                    USER_MSG_CACHE_EXPIRY_DURATION_SECS};
#[cfg(feature = "use-mock-crust")]
use super::common::Testable;
use timer::Timer;
use types::MessageId;

pub struct Client {
    ack_mgr: AckManager,
    crust_service: Service,
    event_sender: Sender<Event>,
    full_id: FullId,
    msg_accumulator: MessageAccumulator,
    peer_mgr: PeerManager,
    request_msg_ids: LruCache<u64, MessageId>,
    signed_msg_filter: SignedMessageFilter,
    stats: Stats,
    timer: Timer,
    user_msg_cache: UserMessageCache,
}

impl Client {
    #[cfg_attr(feature = "clippy", allow(too_many_arguments))]
    pub fn from_bootstrapping(crust_service: Service,
                              event_sender: Sender<Event>,
                              full_id: FullId,
                              peer_mgr: PeerManager,
                              quorum_size: usize,
                              stats: Stats,
                              timer: Timer)
                              -> Self {
        let client = Client {
            ack_mgr: AckManager::new(),
            crust_service: crust_service,
            event_sender: event_sender,
            full_id: full_id,
            msg_accumulator: MessageAccumulator::with_quorum_size(quorum_size),
            peer_mgr: peer_mgr,
            request_msg_ids: LruCache::with_expiry_duration(Duration::from_secs(GROUP_SIZE as u64 *
                                                                                ACK_TIMEOUT_SECS *
                                                                                2)),
            signed_msg_filter: SignedMessageFilter::new(),
            stats: stats,
            timer: timer,
            user_msg_cache: UserMessageCache::with_expiry_duration(
                Duration::from_secs(USER_MSG_CACHE_EXPIRY_DURATION_SECS)),
        };

        client.send_event(Event::Connected);

        debug!("{:?} - State changed to client, quorum size: {}.",
               client,
               quorum_size);

        client
    }

    pub fn handle_action(&mut self, action: Action) -> Transition {
        let result = match action {
            Action::ClientSendRequest { content, dst, priority, result_tx } => {
                let result = if let Ok(src) = common::get_client_authority(&self.crust_service,
                                                                           &self.peer_mgr,
                                                                           self.full_id
                                                                               .public_id()) {
                    let user_msg = UserMessage::Request(content);

                    match self.send_user_message(src, dst, user_msg, priority) {
                        Err(RoutingError::Interface(err)) => Err(err),
                        Err(_) | Ok(_) => Ok(()),
                    }
                } else {
                    Err(InterfaceError::NotConnected)
                };

                result_tx.send(result).is_ok()
            }
            Action::NodeSendMessage { result_tx, .. } => {
                result_tx.send(Err(InterfaceError::InvalidState)).is_ok()
            }
            Action::CloseGroup { result_tx, .. } => result_tx.send(None).is_ok(),
            Action::Name { result_tx } => result_tx.send(*self.name()).is_ok(),
            Action::QuorumSize { result_tx } => {
                // TODO: return the actual quorum size. To do that, we need to
                // extend the MessageAccumulator's API with a method to retrieve it.
                result_tx.send(0).is_ok()
            }
            Action::Timeout(token) => {
                self.handle_timeout(token);
                true
            }
            Action::Terminate => false,
        };

        if result {
            Transition::Stay
        } else {
            Transition::Terminate
        }
    }

    pub fn handle_crust_event(&mut self, crust_event: CrustEvent) -> Transition {
        match crust_event {
            CrustEvent::LostPeer(peer_id) => self.handle_lost_peer(peer_id),
            CrustEvent::NewMessage(peer_id, bytes) => self.handle_new_message(peer_id, bytes),
            _ => {
                debug!("{:?} Unhandled crust event {:?}", self, crust_event);
                Transition::Stay
            }
        }
    }

    fn handle_ack_response(&mut self, ack: u64) -> Transition {
        self.ack_mgr.receive(ack);
        Transition::Stay
    }

    fn handle_timeout(&mut self, token: u64) {
        self.resend_unacknowledged_timed_out_msgs(token);
    }

    fn handle_new_message(&mut self, peer_id: PeerId, bytes: Vec<u8>) -> Transition {
        let result = match serialisation::deserialise(&bytes) {
            Ok(Message::Hop(hop_msg)) => self.handle_hop_message(hop_msg, peer_id),
            Ok(message) => {
                debug!("{:?} - Unhandled new message: {:?}", self, message);
                Ok(Transition::Stay)
            }
            Err(error) => Err(RoutingError::SerialisationError(error)),
        };

        match result {
            Ok(transition) => transition,
            Err(RoutingError::FilterCheckFailed) => Transition::Stay,
            Err(error) => {
                debug!("{:?} - {:?}", self, error);
                Transition::Stay
            }
        }
    }

    /// Sends the given message, possibly splitting it up into smaller parts.
    fn send_user_message(&mut self,
                         src: Authority,
                         dst: Authority,
                         user_msg: UserMessage,
                         priority: u8)
                         -> Result<(), RoutingError> {
        match user_msg {
            UserMessage::Request(ref request) => {
                let hash = maidsafe_utilities::big_endian_sip_hash(&user_msg);
                let _ = self.request_msg_ids.insert(hash, request.message_id());
                self.stats.count_request(request);
            }
            UserMessage::Response(ref response) => self.stats.count_response(response),
        }
        for part in try!(user_msg.to_parts(priority)) {
            try!(self.send_routing_message(RoutingMessage {
                src: src.clone(),
                dst: dst.clone(),
                content: part,
            }));
        }
        Ok(())
    }
}

impl Bootstrapped for Client {
    fn accumulate(&mut self,
                  routing_msg: &RoutingMessage,
                  public_id: &PublicId)
                  -> Result<Option<RoutingMessage>, RoutingError> {
        self.msg_accumulator.add(routing_msg, public_id)
    }

    fn ack_mgr(&self) -> &AckManager {
        &self.ack_mgr
    }

    fn ack_mgr_mut(&mut self) -> &mut AckManager {
        &mut self.ack_mgr
    }

    fn peer_mgr(&self) -> &PeerManager {
        &self.peer_mgr
    }

    fn peer_mgr_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_mgr
    }

    fn resend_unacknowledged_timed_out_msgs(&mut self, token: u64) {
        if let Some((unacked_msg, ack)) = self.ack_mgr.find_timed_out(token) {
            trace!("{:?} - Timed out waiting for ack({}) {:?}",
                   self,
                   ack,
                   unacked_msg);

            if unacked_msg.route as usize == GROUP_SIZE {
                debug!("{:?} - Message unable to be acknowledged - giving up. {:?}",
                       self,
                       unacked_msg);
                self.stats.count_unacked();
                if let MessageContent::UserMessagePart { ref hash, .. } = unacked_msg.routing_msg
                    .content {
                    if let Some(msg_id) = self.request_msg_ids.remove(hash) {
                        trace!("{:?} - Sending RequestTimeout({:?}).", self, msg_id);
                        self.send_event(Event::RequestTimeout(msg_id));
                    }
                }
            } else if let Err(error) =
                   self.send_routing_message_via_route(unacked_msg.routing_msg, unacked_msg.route) {
                debug!("{:?} Failed to send message: {:?}", self, error);
            }
        }
    }

    fn signed_msg_filter(&mut self) -> &mut SignedMessageFilter {
        &mut self.signed_msg_filter
    }

    fn timer(&mut self) -> &mut Timer {
        &mut self.timer
    }
}

impl Debug for Client {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Client({})", self.name())
    }
}

impl DispatchRoutingMessage for Client {
    fn dispatch_routing_message(&mut self,
                                routing_msg: RoutingMessage)
                                -> Result<Transition, RoutingError> {
        let msg_content = routing_msg.content.clone();
        let msg_src = routing_msg.src.clone();
        let msg_dst = routing_msg.dst.clone();

        match msg_content {
            MessageContent::Ack(..) => (),
            _ => {
                trace!("{:?} Got routing message {:?} from {:?} to {:?}.",
                       self,
                       msg_content,
                       msg_src,
                       msg_dst)
            }
        }

        match (msg_content, msg_src, msg_dst) {
            // Ack
            (MessageContent::Ack(ack, _), _, _) => Ok(self.handle_ack_response(ack)),
            // UserMessagePart
            (MessageContent::UserMessagePart { hash, part_count, part_index, payload, .. },
             src,
             dst) => {
                self.handle_user_message_part(hash, part_count, part_index, payload, src, dst);
                Ok(Transition::Stay)
            }
            // other
            _ => {
                debug!("{:?} - Unhandled routing message: {:?}", self, routing_msg);
                Ok(Transition::Stay)
            }
        }
    }
}

impl HandleUserMessage for Client {
    fn add_to_user_msg_cache(&mut self,
                             hash: u64,
                             part_count: u32,
                             part_index: u32,
                             payload: Vec<u8>)
                             -> Option<UserMessage> {
        self.user_msg_cache.add(hash, part_count, part_index, payload)
    }
}

impl ProxyClient for Client {}

impl StateCommon for Client {
    fn crust_service(&self) -> &Service {
        &self.crust_service
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn stats(&mut self) -> &mut Stats {
        &mut self.stats
    }

    fn send_event(&self, event: Event) {
        let _ = self.event_sender.send(event);
    }
}

#[cfg(feature = "use-mock-crust")]
impl Testable for Client {}
