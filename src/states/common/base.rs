// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    core::Core,
    error::{Result, RoutingError},
    id::PublicId,
    location::{DstLocation, SrcLocation},
    log_utils,
    messages::{Message, MessageWithBytes},
    outbox::EventBox,
    quic_p2p::{Peer, Token},
    state_machine::Transition,
    transport::PeerStatus,
    xor_space::XorName,
    NetworkEvent,
};
use bytes::Bytes;
use std::net::SocketAddr;

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
                self.core_mut().transport.disconnect(peer_addr);
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
        if self.core_mut().transport.handle_timeout(token) {
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

        if self.core().msg_filter.contains_incoming(&msg_with_bytes) {
            trace!(
                "not handling message - already handled: {:?}",
                msg_with_bytes
            );
            return Ok(Transition::Stay);
        }

        let msg = msg_with_bytes.take_or_deserialize_message()?;

        if self.should_handle_message(&msg) && self.verify_message(&msg)? {
            self.core_mut().msg_filter.insert_incoming(&msg_with_bytes);
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
        match self.core_mut().handle_unsent_message(addr, msg, msg_token) {
            PeerStatus::Normal => Transition::Stay,
            PeerStatus::Lost => self.handle_peer_lost(addr, outbox),
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
        self.core_mut().transport.target_succeeded(token, addr);
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
            .transport
            .our_connection_info()
            .map_err(|err| {
                debug!("Failed to retrieve our connection info: {:?}", err);
                err.into()
            })
    }

    fn close_group(&self, _name: XorName, _count: usize) -> Option<Vec<XorName>> {
        None
    }

    fn send_message_to_client(&mut self, peer_addr: SocketAddr, msg: Bytes, token: Token) {
        self.core_mut()
            .transport
            .send_message_to_client(peer_addr, msg, token)
    }

    #[cfg(feature = "mock_base")]
    fn process_timers(&mut self) {
        self.core().timer.process_timers()
    }
}
