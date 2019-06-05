// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    crust::{ConnectionInfoResult, CrustError, CrustUser, PrivConnectionInfo},
    error::{InterfaceError, RoutingError},
    id::{FullId, PublicId},
    messages::{DirectMessage, HopMessage, Message, Request, SignedMessage, UserMessage},
    outbox::EventBox,
    routing_table::Authority,
    state_machine::Transition,
    utils::LogIdent,
    xor_name::XorName,
    CrustEvent, NetworkBytes, Service,
};
use maidsafe_utilities::serialisation;
use std::{collections::BTreeSet, fmt::Display, net::SocketAddr};

// Trait for all states.
pub trait Base: Display {
    fn network_service(&self) -> &Service;
    fn full_id(&self) -> &FullId;
    fn in_authority(&self, auth: &Authority<XorName>) -> bool;
    fn min_section_size(&self) -> usize;

    fn log_ident(&self) -> LogIdent {
        LogIdent::new(self)
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
        pub_id: PublicId,
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

    fn handle_network_event(
        &mut self,
        crust_event: CrustEvent<PublicId>,
        outbox: &mut EventBox,
    ) -> Transition {
        let transition = match crust_event {
            CrustEvent::BootstrapAccept(pub_id, peer_kind) => {
                self.handle_bootstrap_accept(pub_id, peer_kind)
            }
            CrustEvent::BootstrapConnect(pub_id, socked_addr) => {
                self.handle_bootstrap_connect(pub_id, socked_addr)
            }
            CrustEvent::BootstrapFailed => self.handle_bootstrap_failed(outbox),
            CrustEvent::ConnectSuccess(pub_id) => self.handle_connect_success(pub_id, outbox),
            CrustEvent::ConnectFailure(pub_id) => self.handle_connect_failure(pub_id, outbox),
            CrustEvent::LostPeer(pub_id) => self.handle_lost_peer(pub_id, outbox),
            CrustEvent::NewMessage(pub_id, _, bytes) => {
                self.handle_new_message(pub_id, bytes, outbox)
            }
            CrustEvent::ConnectionInfoPrepared(ConnectionInfoResult {
                result_token,
                result,
            }) => self.handle_connection_info_prepared(result_token, result),
            CrustEvent::ListenerStarted(port) => self.handle_listener_started(port, outbox),
            CrustEvent::ListenerFailed => self.handle_listener_failed(outbox),
            CrustEvent::WriteMsgSizeProhibitive(pub_id, msg) => {
                self.handle_message_too_large(pub_id, msg)
            }
        };

        if let Transition::Stay = transition {
            self.finish_handle_crust_event(outbox)
        } else {
            transition
        }
    }

    fn handle_bootstrap_accept(&mut self, _pub_id: PublicId, _peer_kind: CrustUser) -> Transition {
        debug!("{} - Unhandled crust event: BootstrapAccept", self);
        Transition::Stay
    }

    fn handle_bootstrap_connect(
        &mut self,
        _pub_id: PublicId,
        _socked_addr: SocketAddr,
    ) -> Transition {
        debug!("{} - Unhandled crust event: BootstrapConnect", self);
        Transition::Stay
    }

    fn handle_bootstrap_failed(&mut self, _outbox: &mut EventBox) -> Transition {
        debug!("{} - Unhandled crust event: BootstrapFailed", self);
        Transition::Stay
    }

    fn handle_connect_success(&mut self, _pub_id: PublicId, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_connect_failure(&mut self, _pub_id: PublicId, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_lost_peer(&mut self, _pub_id: PublicId, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_connection_info_prepared(
        &mut self,
        _result_token: u32,
        _result: Result<PrivConnectionInfo<PublicId>, CrustError>,
    ) -> Transition {
        Transition::Stay
    }

    fn handle_listener_started(&mut self, _port: u16, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_listener_failed(&mut self, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn handle_message_too_large(&mut self, pub_id: PublicId, msg: Vec<u8>) -> Transition {
        error!(
            "{} - Failed to send {}-byte message to {:?}: Message too large.",
            self,
            msg.len(),
            pub_id
        );

        Transition::Stay
    }

    fn handle_new_message(
        &mut self,
        pub_id: PublicId,
        bytes: NetworkBytes,
        outbox: &mut EventBox,
    ) -> Transition {
        let result = from_network_bytes(bytes)
            .and_then(|message| self.handle_new_deserialised_message(pub_id, message, outbox));

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
        pub_id: PublicId,
        message: Message,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        match message {
            Message::Hop(hop_msg) => self.handle_hop_message(hop_msg, pub_id, outbox),
            Message::Direct(direct_msg) => self.handle_direct_message(direct_msg, pub_id, outbox),
        }
    }

    fn finish_handle_crust_event(&mut self, _outbox: &mut EventBox) -> Transition {
        Transition::Stay
    }

    fn id(&self) -> &PublicId {
        self.full_id().public_id()
    }

    fn name(&self) -> &XorName {
        self.full_id().public_id().name()
    }

    fn close_group(&self, _name: XorName, _count: usize) -> Option<Vec<XorName>> {
        None
    }

    fn send_direct_message(&mut self, dst_id: PublicId, message: DirectMessage) {
        self.send_message(&dst_id, Message::Direct(message));
    }

    fn send_message(&mut self, dst_id: &PublicId, message: Message) {
        let priority = message.priority();

        match to_network_bytes(message) {
            Ok(bytes) => {
                self.send_or_drop(dst_id, bytes, priority);
            }
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

    // Sends the given `data` to the peer with the given `dst_id`. If that results in an
    // error, it disconnects from the peer.
    fn send_or_drop(&mut self, dst_id: &PublicId, data: NetworkBytes, priority: u8) {
        if let Err(err) = self.network_service().send(dst_id, data, priority) {
            info!("{} Connection to {} failed: {:?}", self, dst_id, err);
            // TODO: Handle lost peer, but avoid a cascade of sending messages and handling more
            //       lost peers: https://maidsafe.atlassian.net/browse/MAID-1924
            // self.network_service().disconnect(*pub_id);
            // return self.handle_lost_peer(*pub_id).map(|_| Err(err.into()));
        }
    }

    // Serialise HopMessage containing the given signed message.
    fn to_hop_bytes(
        &self,
        signed_msg: SignedMessage,
        route: u8,
        sent_to: BTreeSet<XorName>,
    ) -> Result<NetworkBytes, RoutingError> {
        let hop_msg = HopMessage::new(signed_msg, route, sent_to)?;
        let message = Message::Hop(hop_msg);
        Ok(to_network_bytes(message).map_err(|(err, _)| err)?)
    }
}

fn to_network_bytes(
    message: Message,
) -> Result<NetworkBytes, (serialisation::SerialisationError, Message)> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = serialisation::serialise(&message).map_err(|err| (err, message));

    #[cfg(feature = "mock_serialise")]
    let result = Ok(Box::new(message));

    result
}

pub fn from_network_bytes(data: NetworkBytes) -> Result<Message, RoutingError> {
    #[cfg(not(feature = "mock_serialise"))]
    let result = serialisation::deserialise(&data).map_err(RoutingError::SerialisationError);

    #[cfg(feature = "mock_serialise")]
    let result = Ok(*data);

    result
}
