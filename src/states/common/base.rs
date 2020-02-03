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
    event::Client,
    id::{FullId, PublicId},
    location::{DstLocation, SrcLocation},
    messages::{Message, MessageWithBytes, Variant},
    network_service::NetworkService,
    outbox::EventBox,
    peer_map::PeerMap,
    quic_p2p::{Peer, Token},
    rng::MainRng,
    state_machine::Transition,
    timer::Timer,
    utils::LogIdent,
    xor_space::{Prefix, XorName},
    ConnectionInfo, NetworkEvent,
};
use bytes::Bytes;
use hex_fmt::HexFmt;
use itertools::Itertools;
use log::LogLevel;
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
    fn peer_map(&self) -> &PeerMap;
    fn peer_map_mut(&mut self) -> &mut PeerMap;
    fn timer(&mut self) -> &mut Timer;
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

    fn filter_incoming_message(&mut self, msg: &MessageWithBytes) -> bool;
    fn relay_message(&mut self, msg: &MessageWithBytes) -> Result<()>;
    fn should_handle_message(&self, _msg: &Message) -> bool;
    fn verify_message(&self, msg: &Message) -> Result<bool>;

    fn handle_message(
        &mut self,
        sender: Option<ConnectionInfo>,
        message: Message,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition>;

    fn unhandled_message(&mut self, sender: Option<ConnectionInfo>, message: Message);

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
            Action::HandleTimeout(token) => match self.handle_timeout(token, outbox) {
                Transition::Stay => (),
                transition => {
                    return transition;
                }
            },
            Action::DisconnectClient {
                peer_addr,
                result_tx,
            } => {
                self.peer_map_mut().remove_client(&peer_addr);
                self.disconnect_from(peer_addr);
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

        self.finish_handle_action(outbox)
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

    fn handle_timeout(&mut self, _token: u64, _outbox: &mut dyn EventBox) -> Transition {
        Transition::Stay
    }

    fn finish_handle_action(&mut self, _outbox: &mut dyn EventBox) -> Transition {
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
            ConnectedTo {
                peer: Peer::Node { node_info },
            } => self.handle_connected_to(node_info, outbox),
            ConnectedTo {
                peer: Peer::Client { peer_addr },
            } => {
                self.peer_map_mut().insert_client(peer_addr);
                let client_event = Client::Connected { peer_addr };
                outbox.send_event(From::from(client_event));
                Transition::Stay
            }
            ConnectionFailure { peer_addr, .. } => {
                if self.peer_map().is_known_client(&peer_addr) {
                    let client_event = Client::ConnectionFailure { peer_addr };
                    outbox.send_event(client_event.into());
                    Transition::Stay
                } else {
                    self.handle_connection_failure(peer_addr, outbox)
                }
            }
            NewMessage { peer_addr, msg } => {
                if self.peer_map().is_known_client(&peer_addr) {
                    let client_event = Client::NewMessage { peer_addr, msg };
                    outbox.send_event(client_event.into());
                    Transition::Stay
                } else {
                    self.handle_new_message(peer_addr, msg, outbox)
                }
            }
            UnsentUserMessage {
                peer_addr,
                msg,
                token,
            } => {
                if self.peer_map().is_known_client(&peer_addr) {
                    let client_event = Client::UnsentUserMsg {
                        peer_addr,
                        msg,
                        token,
                    };
                    outbox.send_event(client_event.into());
                    Transition::Stay
                } else {
                    self.handle_unsent_message(peer_addr, msg, token, outbox)
                }
            }
            SentUserMessage {
                peer_addr,
                msg,
                token,
            } => {
                if self.peer_map().is_known_client(&peer_addr) {
                    let client_event = Client::SentUserMsg {
                        peer_addr,
                        msg,
                        token,
                    };
                    outbox.send_event(client_event.into());
                    Transition::Stay
                } else {
                    self.handle_sent_message(peer_addr, msg, token, outbox)
                }
            }
            Finish => Transition::Terminate,
        };

        if let Transition::Stay = transition {
            self.finish_handle_network_event(outbox)
        } else {
            transition
        }
    }

    fn handle_bootstrapped_to(&mut self, _conn_info: ConnectionInfo) -> Transition {
        debug!("{} - Unhandled network event: BootstrappedTo", self);
        Transition::Stay
    }

    fn handle_bootstrap_failure(&mut self, _outbox: &mut dyn EventBox) -> Transition {
        debug!("{} - Unhandled network event: BootstrapFailure", self);
        Transition::Stay
    }

    fn handle_connected_to(
        &mut self,
        conn_info: ConnectionInfo,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        self.peer_map_mut().connect(conn_info);
        Transition::Stay
    }

    fn handle_connection_failure(
        &mut self,
        peer_addr: SocketAddr,
        outbox: &mut dyn EventBox,
    ) -> Transition {
        trace!("{} - ConnectionFailure from {}", self, peer_addr);

        let _ = self.peer_map_mut().disconnect(peer_addr);
        self.handle_peer_lost(peer_addr, outbox)
    }

    fn handle_new_message(
        &mut self,
        src_addr: SocketAddr,
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

        let sender = self.peer_map().get_connection_info(&src_addr).cloned();
        match self.try_handle_message(sender, msg, outbox) {
            Ok(transition) => transition,
            Err(error) => {
                debug!("{} - Failed to handle message: {:?}", self, error);
                Transition::Stay
            }
        }
    }

    fn try_handle_message(
        &mut self,
        sender: Option<ConnectionInfo>,
        msg: MessageWithBytes,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        trace!(
            "{} - try handle message {:?}",
            self,
            HexFmt(msg.full_crypto_hash())
        );

        if !self.filter_incoming_message(&msg) {
            trace!(
                "{} - Known message {:?}, not handling further",
                self,
                HexFmt(msg.full_crypto_hash())
            );

            return Ok(Transition::Stay);
        }

        self.handle_filtered_message(sender, msg, outbox)
    }

    fn handle_filtered_message(
        &mut self,
        sender: Option<ConnectionInfo>,
        mut msg: MessageWithBytes,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition> {
        self.try_relay_message(&msg)?;

        if !self.in_dst_location(msg.message_dst()) {
            return Ok(Transition::Stay);
        }

        let msg = msg.take_or_deserialize_message()?;
        if self.should_handle_message(&msg) && self.verify_message(&msg)? {
            self.handle_message(sender, msg, outbox)
        } else {
            self.unhandled_message(sender, msg);
            Ok(Transition::Stay)
        }
    }

    fn try_relay_message(&mut self, msg: &MessageWithBytes) -> Result<()> {
        if !self.in_dst_location(msg.message_dst()) || msg.message_dst().is_multiple() {
            // Relay closer to the destination or broadcast to the rest of our section.
            self.relay_message(msg)
        } else {
            Ok(())
        }
    }

    fn handle_unsent_message(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
        token: Token,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        let log_ident = LogIdent::new(self);
        self.network_service_mut()
            .send_message_to_next_target(msg, token, peer_addr, log_ident);
        Transition::Stay
    }

    fn handle_sent_message(
        &mut self,
        peer_addr: SocketAddr,
        _msg: Bytes,
        token: Token,
        _outbox: &mut dyn EventBox,
    ) -> Transition {
        trace!(
            "{} Successfully sent message with ID {} to {:?}",
            self,
            token,
            peer_addr
        );
        self.network_service_mut()
            .targets_cache_mut()
            .target_succeeded(token, peer_addr);
        Transition::Stay
    }

    fn finish_handle_network_event(&mut self, _outbox: &mut dyn EventBox) -> Transition {
        Transition::Stay
    }

    fn id(&self) -> &PublicId {
        self.full_id().public_id()
    }

    fn name(&self) -> &XorName {
        self.full_id().public_id().name()
    }

    fn our_connection_info(&mut self) -> Result<ConnectionInfo> {
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

    fn send_direct_message(&mut self, recipient: &ConnectionInfo, variant: Variant) {
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

    fn send_message_to_target(&mut self, dst: &ConnectionInfo, message: Bytes) {
        self.send_message_to_targets(slice::from_ref(dst), 1, message);
    }

    fn send_message_to_targets(
        &mut self,
        conn_infos: &[ConnectionInfo],
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
        conn_infos: &[ConnectionInfo],
        dg_size: usize,
        message: Bytes,
    ) {
        self.network_service_mut()
            .send_message_to_initial_targets(conn_infos, dg_size, message);
    }

    fn send_message_to_client(&mut self, peer_addr: SocketAddr, msg: Bytes, token: Token) {
        let client = Peer::Client { peer_addr };
        self.network_service_mut()
            .service_mut()
            .send(client, msg, token);
    }

    fn disconnect(&mut self, peer_addr: &SocketAddr) {
        if self.peer_map_mut().disconnect(*peer_addr).is_some() {
            info!("{} - Disconnecting from {}", self, peer_addr);
            self.disconnect_from(*peer_addr);
        }
    }

    fn disconnect_from(&mut self, peer_addr: SocketAddr) {
        self.network_service_mut()
            .service_mut()
            .disconnect_from(peer_addr);
    }

    fn log_verify_failure<'a, T, I>(&self, msg: &T, error: &RoutingError, their_key_infos: I)
    where
        T: Debug,
        I: IntoIterator<Item = (&'a Prefix<XorName>, &'a SectionKeyInfo)>,
    {
        log_or_panic!(
            LogLevel::Error,
            "{} - Verification failed: {:?} - {:?} --- [{:?}]",
            self,
            msg,
            error,
            their_key_infos.into_iter().format(", ")
        )
    }
}
