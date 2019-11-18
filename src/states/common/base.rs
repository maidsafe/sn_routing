// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    chain::DevParams,
    error::{InterfaceError, RoutingError},
    id::{FullId, P2pNode, PublicId},
    messages::{
        DirectMessage, HopMessage, Message, RoutingMessage, SignedDirectMessage,
        SignedRoutingMessage,
    },
    outbox::EventBox,
    peer_map::PeerMap,
    quic_p2p::{Peer, Token},
    rng::MainRng,
    routing_table::Authority,
    state_machine::Transition,
    timer::Timer,
    utils::LogIdent,
    xor_name::XorName,
    ClientEvent, ConnectionInfo, NetworkBytes, NetworkEvent, NetworkService,
};
use log::LogLevel;
use maidsafe_utilities::serialisation;
use std::{fmt::Display, net::SocketAddr, slice};

// Trait for all states.
pub trait Base: Display {
    fn network_service(&self) -> &NetworkService;
    fn network_service_mut(&mut self) -> &mut NetworkService;
    fn full_id(&self) -> &FullId;
    fn in_authority(&self, auth: &Authority<XorName>) -> bool;
    fn peer_map(&self) -> &PeerMap;
    fn peer_map_mut(&mut self) -> &mut PeerMap;
    fn timer(&mut self) -> &mut Timer;
    fn send_routing_message(&mut self, routing_msg: RoutingMessage) -> Result<(), RoutingError>;
    fn rng(&mut self) -> &mut MainRng;
    fn dev_params(&self) -> &DevParams;
    fn dev_params_mut(&mut self) -> &mut DevParams;

    fn log_ident(&self) -> LogIdent {
        LogIdent::new(self)
    }

    fn handle_peer_lost(&mut self, _pub_id: PublicId, _outbox: &mut dyn EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        p2p_node: P2pNode,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError>;

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError>;

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
            Action::GetId { result_tx } => {
                let _ = result_tx.send(*self.id());
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
                self.send_msg_to_client(peer_addr, msg, token);
                let _ = result_tx.send(Ok(()));
            }
            Action::Terminate => {
                return Transition::Terminate;
            }
        }

        self.finish_handle_action(outbox)
    }

    fn handle_send_message(
        &mut self,
        _src: Authority<XorName>,
        _dst: Authority<XorName>,
        _content: Vec<u8>,
    ) -> Result<(), InterfaceError> {
        warn!("{} - Cannot handle SendMessage - invalid state.", self);
        Err(InterfaceError::InvalidState)
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
                let client_event = ClientEvent::ConnectedToClient { peer_addr };
                outbox.send_event(From::from(client_event));
                Transition::Stay
            }
            ConnectionFailure { peer_addr, .. } => {
                if self.peer_map().is_known_client(&peer_addr) {
                    let client_event = ClientEvent::ConnectionFailureToClient { peer_addr };
                    outbox.send_event(client_event.into());
                    Transition::Stay
                } else {
                    self.handle_connection_failure(peer_addr, outbox)
                }
            }
            NewMessage { peer_addr, msg } => {
                if self.peer_map().is_known_client(&peer_addr) {
                    let client_event = ClientEvent::NewMessageFromClient { peer_addr, msg };
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
                    let client_event = ClientEvent::UnsentUserMsgToClient {
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
                    let client_event = ClientEvent::SentUserMsgToClient {
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

        let mut transition = Transition::Stay;

        let pub_ids = self.peer_map_mut().disconnect(peer_addr);
        for pub_id in pub_ids {
            trace!("{} - ConnectionFailure from {}", self, pub_id);
            let other_transition = self.handle_peer_lost(pub_id, outbox);

            if let Transition::Stay = transition {
                transition = other_transition
            }
        }

        transition
    }

    fn handle_new_message(
        &mut self,
        src_addr: SocketAddr,
        bytes: NetworkBytes,
        outbox: &mut dyn EventBox,
    ) -> Transition {
        let result = from_network_bytes(bytes)
            .and_then(|message| self.handle_new_deserialised_message(src_addr, message, outbox));

        match result {
            Ok(transition) => transition,
            Err(RoutingError::FilterCheckFailed) => Transition::Stay,
            Err(err) => {
                debug!("{} - {:?}", self, err);
                Transition::Stay
            }
        }
    }

    fn handle_new_deserialised_message(
        &mut self,
        src_addr: SocketAddr,
        message: Message,
        outbox: &mut dyn EventBox,
    ) -> Result<Transition, RoutingError> {
        match message {
            Message::Hop(msg) => self.handle_hop_message(msg, outbox),
            Message::Direct(msg) => {
                let (msg, public_id) = msg.open()?;
                self.peer_map_mut().identify(public_id, src_addr);
                let connection_info =
                    if let Some(connection_info) = self.peer_map().get_connection_info(public_id) {
                        connection_info.clone()
                    } else {
                        trace!(
                            "{} - Received direct message from unconnected peer {}: {:?}",
                            self,
                            public_id,
                            msg
                        );
                        return Ok(Transition::Stay);
                    };

                self.handle_direct_message(msg, P2pNode::new(public_id, connection_info), outbox)
            }
        }
    }

    fn handle_unsent_message(
        &mut self,
        peer_addr: SocketAddr,
        msg: NetworkBytes,
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
        _msg: NetworkBytes,
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

    fn our_connection_info(&mut self) -> Result<ConnectionInfo, RoutingError> {
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

    fn send_direct_message(&mut self, dst: &ConnectionInfo, content: DirectMessage) {
        let message = if let Ok(message) = self.to_signed_direct_message(content) {
            message
        } else {
            return;
        };

        self.send_message(dst, message);
    }

    fn send_message(&mut self, dst: &ConnectionInfo, message: Message) {
        self.send_message_to_targets(slice::from_ref(dst), 1, message);
    }

    fn send_message_to_targets(
        &mut self,
        conn_infos: &[ConnectionInfo],
        dg_size: usize,
        message: Message,
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
        message: Message,
    ) {
        let bytes = match to_network_bytes(&message) {
            Ok(bytes) => bytes,
            Err((error, message)) => {
                error!(
                    "{} Failed to serialise message {:?}: {:?}",
                    self, message, error
                );
                // The caller can't do much to handle this except log more messages, so just stop
                // trying to send here and let other mechanisms handle the lost message. If the
                // node drops too many messages, it should fail to join the network anyway.
                return;
            }
        };

        self.network_service_mut()
            .send_message_to_initial_targets(conn_infos, dg_size, bytes);
    }

    // Create HopMessage containing the given signed message.
    fn to_hop_message(&self, signed_msg: SignedRoutingMessage) -> Result<Message, RoutingError> {
        let hop_msg = HopMessage::new(signed_msg)?;
        Ok(Message::Hop(hop_msg))
    }

    fn to_signed_direct_message(&self, content: DirectMessage) -> Result<Message, RoutingError> {
        SignedDirectMessage::new(content, self.full_id())
            .map(Message::Direct)
            .map_err(|err| {
                error!("{} - Failed to create SignedDirectMessage: {:?}", self, err);
                err
            })
    }

    fn disconnect(&mut self, pub_id: &PublicId) {
        if let Some(conn_info) = self.peer_map_mut().remove(pub_id) {
            info!("{} - Disconnecting from {}", self, pub_id);
            self.disconnect_from(conn_info.peer_addr);
        }
    }

    fn disconnect_from(&mut self, peer_addr: SocketAddr) {
        self.network_service_mut()
            .service_mut()
            .disconnect_from(peer_addr);
    }

    fn send_msg_to_client(&mut self, peer_addr: SocketAddr, msg: NetworkBytes, token: Token) {
        let client = Peer::Client { peer_addr };
        self.network_service_mut()
            .service_mut()
            .send(client, msg, token);
    }

    fn check_signed_message_integrity(
        &self,
        msg: &SignedRoutingMessage,
    ) -> Result<(), RoutingError> {
        msg.check_integrity().map_err(|err| {
            log_or_panic!(
                LogLevel::Error,
                "{} Invalid integrity of {:?}: {:?}",
                self,
                msg,
                err,
            );
            err
        })
    }
}

pub fn to_network_bytes(
    message: &Message,
) -> Result<NetworkBytes, (serialisation::SerialisationError, &Message)> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = Ok(NetworkBytes::from(
        serialisation::serialise(message).map_err(|err| (err, message))?,
    ));

    #[cfg(feature = "mock_serialise")]
    let result = Ok(NetworkBytes::new(message.clone()));

    result
}

pub fn from_network_bytes(data: NetworkBytes) -> Result<Message, RoutingError> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = serialisation::deserialise(&data[..]).map_err(RoutingError::SerialisationError);

    #[cfg(feature = "mock_serialise")]
    let result = Ok((*data).clone());

    result
}
