// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    chain::SectionKeyInfo,
    error::{Result, RoutingError},
    id::{FullId, PublicId},
    location::{DstLocation, SrcLocation},
    messages::{Message, MessageWithBytes, Variant},
    network_service::{NetworkService, Resend},
    outbox::EventBox,
    quic_p2p::{Peer, Token},
    rng::MainRng,
    state_machine::Transition,
    time::Duration,
    timer::Timer,
    utils::LogIdent,
    xor_space::{Prefix, XorName},
    NetworkEvent,
};
use bytes::Bytes;
use itertools::Itertools;
use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
    slice,
};

// Trait for all states.
pub trait Base: Display {
    fn network_service(&self) -> &NetworkService;
    fn network_service_mut(&mut self) -> &mut NetworkService;
    fn full_id(&self) -> &FullId;
    fn in_dst_location(&self, dst: &DstLocation) -> bool;
    fn timer(&self) -> &Timer;
    fn rng(&mut self) -> &mut MainRng;

    fn log_ident(&self) -> LogIdent {
        LogIdent::new(self)
    }

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
                self.network_service_mut().disconnect(peer_addr);
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
        warn!("{} - Cannot handle SendMessage - invalid state.", self);
        Err(RoutingError::InvalidState)
    }

    fn invoke_handle_timeout(&mut self, token: u64, outbox: &mut dyn EventBox) -> Transition {
        if self.network_service_mut().handle_timeout(token) {
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

    fn finish_handle_transition(&mut self, _outbox: &mut dyn EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_network_event(
        &mut self,
        event: NetworkEvent,
        outbox: &mut dyn EventBox,
    ) -> Transition {
        use crate::NetworkEvent::*;

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
        debug!("{} - Unhandled network event: BootstrappedTo", self);
        Transition::Stay
    }

    fn handle_bootstrap_failure(&mut self, _outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - Unhandled network event: BootstrapFailure", self);
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
        trace!("{} - ConnectionFailure from {}", self, addr);
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
                debug!("{} - Failed to deserialize message: {:?}", self, error);
                return Transition::Stay;
            }
        };

        match self.try_handle_message(Some(sender), msg, outbox) {
            Ok(transition) => transition,
            Err(error) => {
                debug!("{} - Failed to handle message: {:?}", self, error);
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
        trace!(
            "{} - try handle message {:?}",
            self,
            msg_with_bytes.full_crypto_hash()
        );

        self.try_relay_message(sender, &msg_with_bytes)?;

        if !self.in_dst_location(msg_with_bytes.message_dst()) {
            return Ok(Transition::Stay);
        }

        if self.is_message_handled(&msg_with_bytes) {
            trace!(
                "{} - not handling message - already handled: {:?}",
                self,
                msg_with_bytes.full_crypto_hash()
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
        match self.network_service_mut().target_failed(msg_token, addr) {
            Resend::Now(next_target) => {
                trace!(
                    "{} - Sending message ID {} to {} failed - resending to {} now",
                    self,
                    msg_token,
                    addr,
                    next_target
                );

                self.network_service_mut()
                    .send_now(next_target, msg, msg_token);
                Transition::Stay
            }
            Resend::Later(next_target, delay) => {
                trace!(
                    "{} - Sending message ID {} to {} failed - resending to {} in {:?}",
                    self,
                    msg_token,
                    addr,
                    next_target,
                    delay
                );

                let timer_token = self.timer().schedule(delay);
                self.network_service_mut()
                    .send_later(next_target, msg, msg_token, timer_token);
                Transition::Stay
            }
            Resend::Never => {
                trace!(
                    "{} - Sending message ID {} to {} failed too many times - giving up.",
                    self,
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
        trace!(
            "{} Successfully sent message with ID {} to {:?}",
            self,
            token,
            addr
        );
        self.network_service_mut()
            .targets_cache_mut()
            .target_succeeded(token, addr);
        Transition::Stay
    }

    fn id(&self) -> &PublicId {
        self.full_id().public_id()
    }

    fn name(&self) -> &XorName {
        self.full_id().public_id().name()
    }

    fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.network_service_mut()
            .service_mut()
            .our_connection_info()
            .map_err(|err| {
                debug!(
                    "{} - Failed to retrieve our connection info: {:?}",
                    self, err
                );
                err.into()
            })
    }

    fn close_group(&self, _name: XorName, _count: usize) -> Option<Vec<XorName>> {
        None
    }

    fn send_direct_message(&mut self, recipient: &SocketAddr, variant: Variant) {
        let message = match Message::single_src(self.full_id(), DstLocation::Direct, variant) {
            Ok(message) => message,
            Err(error) => {
                error!("{} - Failed to create message: {:?}", self, error);
                return;
            }
        };

        let bytes = match message.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                error!(
                    "{} - Failed to serialize message {:?}: {:?}",
                    self, message, error
                );
                return;
            }
        };

        self.send_message_to_target(recipient, bytes)
    }

    fn send_message_to_target(&mut self, dst: &SocketAddr, message: Bytes) {
        self.send_message_to_targets(slice::from_ref(dst), 1, message);
    }

    fn send_message_to_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        dg_size: usize,
        message: Bytes,
    ) {
        if conn_infos.len() < dg_size {
            warn!(
                "{} Less than dg_size valid targets! dg_size = {}; targets = {:?}; msg = {:?}",
                self, dg_size, conn_infos, message
            );
        }

        self.send_message_to_initial_targets(conn_infos, dg_size, message);
    }

    fn send_message_to_initial_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        dg_size: usize,
        message: Bytes,
    ) {
        let token = self
            .network_service_mut()
            .send_message_to_initial_targets(conn_infos, dg_size, message);
        trace!(
            "{} Sending message ID {} to {:?}",
            self,
            token,
            &conn_infos[..dg_size.min(conn_infos.len())]
        );
    }

    fn send_message_to_target_later(&mut self, dst: &SocketAddr, message: Bytes, delay: Duration) {
        let timer_token = self.timer().schedule(delay);
        self.network_service_mut()
            .send_message_to_target_later(dst, message, timer_token)
    }

    fn send_message_to_client(&mut self, peer_addr: SocketAddr, msg: Bytes, token: Token) {
        let client = Peer::Client(peer_addr);
        self.network_service_mut()
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
            "{} - Verification failed: {:?} - {:?} --- [{:?}]",
            self,
            msg,
            error,
            their_key_infos.into_iter().format(", ")
        )
    }

    #[cfg(feature = "mock_base")]
    fn process_timers(&mut self) {
        self.timer().process_timers()
    }
}
