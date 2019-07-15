// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    error::{InterfaceError, RoutingError},
    id::{FullId, PublicId},
    messages::{
        DirectMessage, HopMessage, Message, Request, SignedDirectMessage, SignedRoutingMessage,
        UserMessage,
    },
    outbox::EventBox,
    peer_map::PeerMap,
    quic_p2p::NodeInfo,
    routing_table::Authority,
    state_machine::Transition,
    utils::LogIdent,
    xor_name::XorName,
    ConnectionInfo, NetworkBytes, NetworkEvent, NetworkService,
};
use maidsafe_utilities::serialisation;
use std::{fmt::Display, net::SocketAddr};

// Trait for all states.
pub trait Base: Display {
    fn network_service(&self) -> &NetworkService;
    fn network_service_mut(&mut self) -> &mut NetworkService;
    fn full_id(&self) -> &FullId;
    fn in_authority(&self, auth: &Authority<XorName>) -> bool;
    fn min_section_size(&self) -> usize;
    fn peer_map(&self) -> &PeerMap;
    fn peer_map_mut(&mut self) -> &mut PeerMap;

    fn log_ident(&self) -> LogIdent {
        LogIdent::new(self)
    }

    fn handle_peer_lost(&mut self, _pub_id: PublicId, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_direct_message(
        &mut self,
        msg: DirectMessage,
        pub_id: PublicId,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError>;

    fn handle_hop_message(
        &mut self,
        msg: HopMessage,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError>;

    fn handle_action(&mut self, action: Action, outbox: &mut EventBox) -> Transition {
        match action {
            Action::ClientSendRequest {
                dst,
                content,
                priority,
                result_tx,
            } => {
                let result = self.handle_client_send_request(dst, content, priority);
                let _ = result_tx.send(result);
            }
            Action::NodeSendMessage {
                src,
                dst,
                content,
                priority,
                result_tx,
            } => {
                let result = self.handle_node_send_message(src, dst, content, priority);
                let _ = result_tx.send(result);
            }
            Action::GetId { result_tx } => {
                let _ = result_tx.send(*self.id());
            }
            Action::HandleTimeout(token) => {
                if let Transition::Terminate = self.handle_timeout(token, outbox) {
                    return Transition::Terminate;
                }
            }
            Action::TakeResourceProofResult(pub_id, messages) => {
                self.handle_resource_proof_result(pub_id, messages);
            }
            Action::Terminate => {
                return Transition::Terminate;
            }
        }

        self.finish_handle_action(outbox)
    }

    fn handle_client_send_request(
        &mut self,
        _dst: Authority<XorName>,
        _content: Request,
        _priority: u8,
    ) -> Result<(), InterfaceError> {
        warn!(
            "{} - Cannot handle ClientSendRequest - invalid state.",
            self
        );
        Err(InterfaceError::InvalidState)
    }

    fn handle_node_send_message(
        &mut self,
        _src: Authority<XorName>,
        _dst: Authority<XorName>,
        _content: UserMessage,
        _priority: u8,
    ) -> Result<(), InterfaceError> {
        warn!("{} - Cannot handle NodeSendMessage - invalid state.", self);
        Err(InterfaceError::InvalidState)
    }

    fn handle_timeout(&mut self, _token: u64, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_resource_proof_result(&mut self, _pub_id: PublicId, _messages: Vec<DirectMessage>) {
        error!(
            "{} - Action::ResourceProofResult received by invalid state",
            self
        );
    }

    fn finish_handle_action(&mut self, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_network_event(&mut self, event: NetworkEvent, outbox: &mut EventBox) -> Transition {
        use crate::NetworkEvent::*;

        let transition = match event {
            BootstrappedTo { node } => self.handle_bootstrapped_to(node),
            BootstrapFailure => self.handle_bootstrap_failure(outbox),
            ConnectedTo { peer } => self.handle_connected_to(peer, outbox),
            ConnectionFailure { peer_addr, .. } => {
                self.handle_connection_failure(peer_addr, outbox)
            }
            NewMessage { peer_addr, msg } => self.handle_new_message(peer_addr, msg, outbox),
            UnsentUserMessage {
                peer_addr,
                msg,
                token,
            } => self.handle_unsent_message(peer_addr, msg, token, outbox),
            SentUserMessage {
                peer_addr,
                msg,
                token,
            } => self.handle_sent_message(peer_addr, msg, token, outbox),
            Finish => Transition::Terminate,
        };

        if let Transition::Stay = transition {
            self.finish_handle_network_event(outbox)
        } else {
            transition
        }
    }

    fn handle_bootstrapped_to(&mut self, _node_info: NodeInfo) -> Transition {
        debug!("{} - Unhandled network event: BootstrappedTo", self);
        Transition::Stay
    }

    fn handle_bootstrap_failure(&mut self, _outbox: &mut EventBox) -> Transition {
        debug!("{} - Unhandled network event: BootstrapFailure", self);
        Transition::Stay
    }

    fn handle_connected_to(
        &mut self,
        conn_info: ConnectionInfo,
        _outbox: &mut EventBox,
    ) -> Transition {
        self.peer_map_mut().connect(conn_info);
        Transition::Stay
    }

    fn handle_connection_failure(
        &mut self,
        peer_addr: SocketAddr,
        outbox: &mut EventBox,
    ) -> Transition {
        trace!("{} - ConnectionFailure from {}", self, peer_addr);

        if let Some(pub_id) = self.peer_map_mut().disconnect(peer_addr) {
            trace!("{} - ConnectionFailure from {}", self, pub_id);
            self.handle_peer_lost(pub_id, outbox)
        } else {
            Transition::Stay
        }
    }

    fn handle_new_message(
        &mut self,
        src_addr: SocketAddr,
        bytes: NetworkBytes,
        outbox: &mut EventBox,
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
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        match message {
            Message::Hop(msg) => self.handle_hop_message(msg, outbox),
            Message::Direct(msg) => {
                let (msg, pub_id) = msg.open()?;
                self.peer_map_mut().identify(pub_id, src_addr);
                self.handle_direct_message(msg, pub_id, outbox)
            }
        }
    }

    fn handle_unsent_message(
        &mut self,
        peer_addr: SocketAddr,
        msg: NetworkBytes,
        msg_id: u64,
        _outbox: &mut EventBox,
    ) -> Transition {
        let log_ident = LogIdent::new(self);
        self.network_service_mut()
            .send_message_to_next_target(msg, msg_id, peer_addr, log_ident);
        Transition::Stay
    }

    fn handle_sent_message(
        &mut self,
        peer_addr: SocketAddr,
        _msg: NetworkBytes,
        msg_id: u64,
        _outbox: &mut EventBox,
    ) -> Transition {
        debug!(
            "{} Successfully sent message with ID {} to {:?}",
            self, msg_id, peer_addr
        );
        self.network_service_mut()
            .targets_cache_mut()
            .target_succeeded(msg_id, peer_addr);
        Transition::Stay
    }

    fn finish_handle_network_event(&mut self, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn id(&self) -> &PublicId {
        self.full_id().public_id()
    }

    fn name(&self) -> &XorName {
        self.full_id().public_id().name()
    }

    fn our_connection_info(&mut self) -> Result<NodeInfo, RoutingError> {
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

    fn send_direct_message(&mut self, dst_id: &PublicId, content: DirectMessage) {
        let message = if let Ok(message) = self.to_signed_direct_message(content) {
            message
        } else {
            return;
        };

        self.send_message(dst_id, message);
    }

    fn send_message(&mut self, dst_id: &PublicId, message: Message) {
        self.send_message_to_targets(&[*dst_id], 1, message);
    }

    fn send_message_to_targets(
        &mut self,
        dst_targets: &[PublicId],
        dg_size: usize,
        message: Message,
    ) {
        let msg_id = self.network_service_mut().next_msg_id();
        let conn_infos: Vec<_> = dst_targets
            .iter()
            .filter_map(|pub_id| self.peer_map().get_connection_info(pub_id).cloned())
            .collect();

        if conn_infos.len() < dg_size {
            warn!(
                "{} Less than dg_size valid targets! dg_size = {}; targets = {:?}; msg = {:?}",
                self,
                dg_size,
                dst_targets
                    .iter()
                    .filter(|pub_id| self.peer_map().get_connection_info(pub_id).is_some()),
                message
            );
        }

        // initially only send to dg_size targets
        for conn_info in conn_infos.iter().take(dg_size) {
            self.send_message_over_network(conn_info.clone(), &message, msg_id);
        }

        self.network_service_mut()
            .targets_cache_mut()
            .insert_message(msg_id, conn_infos, dg_size);
    }

    fn send_message_over_network(
        &mut self,
        conn_info: ConnectionInfo,
        message: &Message,
        msg_id: u64,
    ) {
        match to_network_bytes(message) {
            Ok(bytes) => self
                .network_service_mut()
                .service_mut()
                .send(conn_info, bytes, msg_id),
            Err((error, message)) => {
                error!(
                    "{} Failed to serialise message {:?}: {:?}",
                    self, message, error
                );
                // The caller can't do much to handle this except log more messages, so just stop
                // trying to send here and let other mechanisms handle the lost message. If the
                // node drops too many messages, it should fail to join the network anyway.
            }
        };
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
}

pub fn to_network_bytes(
    message: &Message,
) -> Result<NetworkBytes, (serialisation::SerialisationError, &Message)> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = Ok(NetworkBytes::from(
        serialisation::serialise(message).map_err(|err| (err, message))?,
    ));

    #[cfg(feature = "mock_serialise")]
    let result = Ok(Box::new(message.clone()));

    result
}

pub fn from_network_bytes(data: NetworkBytes) -> Result<Message, RoutingError> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = serialisation::deserialise(&data[..]).map_err(RoutingError::SerialisationError);

    #[cfg(feature = "mock_serialise")]
    let result = Ok(*data);

    result
}
