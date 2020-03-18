// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Core;
use crate::{
    action::Action,
    chain::SectionKeyInfo,
    error::{Result, RoutingError},
    id::PublicId,
    location::{DstLocation, SrcLocation},
    log_utils,
    messages::{Message, MessageWithBytes, Variant},
    network_service::Resend,
    outbox::EventBox,
    quic_p2p::{Peer, Token},
    state_machine::Transition,
    time::Duration,
    xor_space::{Prefix, XorName},
    NetworkEvent,
};
use bytes::Bytes;
use itertools::Itertools;
use std::{fmt::Debug, net::SocketAddr, slice};

// Trait for all states.
pub trait Base {
    fn core(&self) -> &Core;
    fn core_mut(&mut self) -> &mut Core;
    fn in_dst_location(&self, dst: &DstLocation) -> bool;

    fn set_log_ident(&self) -> log_utils::Guard;

    fn handle_peer_lost(
        &mut self,
        _peer_addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        Transition::Stay
    }

    fn is_message_handled(&self, msg: &MessageWithBytes) -> bool;
    fn set_message_handled(&mut self, msg: &MessageWithBytes);
    fn relay_message(&mut self, sender: Option<SocketAddr>, msg: &MessageWithBytes) -> Result<()>;
    fn should_handle_message(&self, _msg: &Message) -> bool;
    fn verify_message(&self, msg: &Message) -> Result<bool>;

    fn handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        message: Message,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition>;

    fn unhandled_message(&mut self, sender: Option<SocketAddr>, msg: Message, msg_bytes: Bytes);

    fn handle_action(&mut self, action: Action, outbox: &mut dyn EventBox) -> Transition {
        let _log_ident = self.set_log_ident();

        match action {
            Action::SendMessage {
                src,
                dst,
                content,
                result_tx,
            } => {
                let result = self.handle_send_message(src, dst, content);
                let _ = result_tx.send(result);
            }
            Action::HandleTimeout(token) => match self.invoke_handle_timeout(token, outbox) {
                Transition::Stay => (),
                transition => {
                    return transition;
                }
            },
            Action::DisconnectClient {
                peer_addr,
                result_tx,
            } => {
                self.core_mut().network_service.disconnect(peer_addr);
                let _ = result_tx.send(Ok(()));
            }
            Action::SendMessageToClient {
                peer_addr,
                msg,
                token,
                result_tx,
            } => {
                self.send_message_to_client(peer_addr, msg, token);
                let _ = result_tx.send(Ok(()));
            }
        }

        self.finish_handle_input(outbox)
    }

    fn handle_send_message(
        &mut self,
        _src: SrcLocation,
        _dst: DstLocation,
        _content: Vec<u8>,
    ) -> Result<(), RoutingError> {
        warn!("Cannot handle SendMessage - invalid state.");
        Err(RoutingError::InvalidState)
    }

    fn invoke_handle_timeout(&mut self, token: u64, outbox: &mut dyn EventBox) -> Transition {
        if self.core_mut().network_service.handle_timeout(token) {
            Transition::Stay
        } else {
            self.handle_timeout(token, outbox)
        }
    }

    fn handle_timeout(&mut self, _token: u64, _outbox: &mut dyn EventBox) -> Transition {
        Transition::Stay
    }

    fn finish_handle_input(&mut self, _outbox: &mut dyn EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_network_event(
        &mut self,
        event: NetworkEvent,
        outbox: &mut dyn EventBox,
    ) -> Transition {
        use crate::NetworkEvent::*;

        let _log_ident = self.set_log_ident();

        let transition = match event {
            BootstrappedTo { node } => self.handle_bootstrapped_to(node),
            BootstrapFailure => self.handle_bootstrap_failure(outbox),
            ConnectedTo { peer } => match peer {
                Peer::Client(_) => Transition::Stay,
                Peer::Node(peer_addr) => self.handle_connected_to(peer_addr, outbox),
            },
            ConnectionFailure { peer, .. } => match peer {
                Peer::Client(_) => Transition::Stay,
                Peer::Node(peer_addr) => self.handle_connection_failure(peer_addr, outbox),
            },
            NewMessage { peer, msg } => match peer {
                Peer::Client(_) => Transition::Stay,
                Peer::Node(peer_addr) => self.handle_new_message(peer_addr, msg, outbox),
            },
            UnsentUserMessage { peer, msg, token } => match peer {
                Peer::Client(_) => Transition::Stay,
                Peer::Node(peer_addr) => self.handle_unsent_message(peer_addr, msg, token, outbox),
            },
            SentUserMessage { peer, msg, token } => match peer {
                Peer::Client(_) => Transition::Stay,
                Peer::Node(peer_addr) => self.handle_sent_message(peer_addr, msg, token, outbox),
            },
            Finish => Transition::Terminate,
        };

        if let Transition::Stay = transition {
            self.finish_handle_input(outbox)
        } else {
            transition
        }
    }

    fn handle_bootstrapped_to(&mut self, _addr: SocketAddr) -> Transition {
        debug!("Unhandled network event: BootstrappedTo");
        Transition::Stay
    }

    fn handle_bootstrap_failure(&mut self, _outbox: &mut dyn EventBox) -> Transition {
        debug!("Unhandled network event: BootstrapFailure");
        Transition::Stay
    }

    fn handle_connected_to(&mut self, _addr: SocketAddr, _outbox: &mut dyn EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_connection_failure(
        &mut self,
        addr: SocketAddr,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        trace!("ConnectionFailure from {}", addr);
        Transition::Stay
    }

    fn handle_new_message(
        &mut self,
        sender: SocketAddr,
        bytes: Bytes,
        outbox: &mut dyn EventBox,
    ) -> Transition {
        let msg = match MessageWithBytes::partial_from_bytes(bytes) {
            Ok(msg) => msg,
            Err(error) => {
                debug!("Failed to deserialize message: {:?}", error);
                return Transition::Stay;
            }
        };

        match self.try_handle_message(Some(sender), msg, outbox) {
            Ok(transition) => transition,
            Err(error) => {
                debug!("Failed to handle message: {:?}", error);
                Transition::Stay
            }
        }
    }

    fn try_handle_message(
        &mut self,
        sender: Option<SocketAddr>,
        mut msg_with_bytes: MessageWithBytes,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        trace!("try handle message {:?}", msg_with_bytes);

        self.try_relay_message(sender, &msg_with_bytes)?;

        if !self.in_dst_location(msg_with_bytes.message_dst()) {
            return Ok(Transition::Stay);
        }

        if self.is_message_handled(&msg_with_bytes) {
            trace!(
                "not handling message - already handled: {:?}",
                msg_with_bytes
            );
            return Ok(Transition::Stay);
        }

        let msg = msg_with_bytes.take_or_deserialize_message()?;

        if self.should_handle_message(&msg) && self.verify_message(&msg)? {
            self.set_message_handled(&msg_with_bytes);
            self.handle_message(sender, msg, outbox)
        } else {
            self.unhandled_message(sender, msg, msg_with_bytes.full_bytes().clone());
            Ok(Transition::Stay)
        }
    }

    fn try_relay_message(
        &mut self,
        sender: Option<SocketAddr>,
        msg: &MessageWithBytes,
    ) -> Result<()> {
        if !self.in_dst_location(msg.message_dst()) || msg.message_dst().is_multiple() {
            // Relay closer to the destination or broadcast to the rest of our section.
            self.relay_message(sender, msg)
        } else {
            Ok(())
        }
    }

    fn handle_unsent_message(
        &mut self,
        addr: SocketAddr,
        msg: Bytes,
        msg_token: Token,
        outbox: &mut dyn EventBox,
    ) -> Transition {
        match self
            .core_mut()
            .network_service
            .target_failed(msg_token, addr)
        {
            Resend::Now(next_target) => {
                trace!(
                    "Sending message ID {} to {} failed - resending to {} now",
                    msg_token,
                    addr,
                    next_target
                );

                self.core_mut()
                    .network_service
                    .send_now(next_target, msg, msg_token);
                Transition::Stay
            }
            Resend::Later(next_target, delay) => {
                trace!(
                    "Sending message ID {} to {} failed - resending to {} in {:?}",
                    msg_token,
                    addr,
                    next_target,
                    delay
                );

                let timer_token = self.core().timer.schedule(delay);
                self.core_mut().network_service.send_later(
                    next_target,
                    msg,
                    msg_token,
                    timer_token,
                );
                Transition::Stay
            }
            Resend::Never => {
                trace!(
                    "Sending message ID {} to {} failed too many times - giving up.",
                    msg_token,
                    addr,
                );

                self.handle_peer_lost(addr, outbox)
            }
        }
    }

    fn handle_sent_message(
        &mut self,
        addr: SocketAddr,
        _msg: Bytes,
        token: Token,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        trace!("Successfully sent message with ID {} to {:?}", token, addr);
        self.core_mut()
            .network_service
            .targets_cache_mut()
            .target_succeeded(token, addr);
        Transition::Stay
    }

    fn id(&self) -> &PublicId {
        self.core().full_id.public_id()
    }

    fn name(&self) -> &XorName {
        self.core().full_id.public_id().name()
    }

    fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.core_mut()
            .network_service
            .service_mut()
            .our_connection_info()
            .map_err(|err| {
                debug!("Failed to retrieve our connection info: {:?}", err);
                err.into()
            })
    }

    fn close_group(&self, _name: XorName, _count: usize) -> Option<Vec<XorName>> {
        None
    }

    fn send_direct_message(&mut self, recipient: &SocketAddr, variant: Variant) {
        let message = match Message::single_src(&self.core().full_id, DstLocation::Direct, variant)
        {
            Ok(message) => message,
            Err(error) => {
                error!("Failed to create message: {:?}", error);
                return;
            }
        };

        let bytes = match message.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                error!("Failed to serialize message {:?}: {:?}", message, error);
                return;
            }
        };

        self.core_mut().network_service.send_message_to_targets(
            slice::from_ref(recipient),
            1,
            bytes,
        )
    }

    fn send_message_to_target_later(&mut self, dst: &SocketAddr, message: Bytes, delay: Duration) {
        let timer_token = self.core().timer.schedule(delay);
        self.core_mut()
            .network_service
            .send_message_to_target_later(dst, message, timer_token)
    }

    fn send_message_to_client(&mut self, peer_addr: SocketAddr, msg: Bytes, token: Token) {
        let client = Peer::Client(peer_addr);
        self.core_mut()
            .network_service
            .service_mut()
            .send(client, msg, token);
    }

    fn log_verify_failure<'a, T, I>(&self, msg: &T, error: &RoutingError, their_key_infos: I)
    where
        T: Debug,
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        log_or_panic!(
            log::Level::Error,
            "Verification failed: {:?} - {:?} --- [{:?}]",
            msg,
            error,
            their_key_infos.into_iter().format(", ")
        )
    }

    #[cfg(feature = "mock_base")]
    fn process_timers(&mut self) {
        self.core().timer.process_timers()
    }
}
