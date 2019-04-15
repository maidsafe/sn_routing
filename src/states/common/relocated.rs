// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::bootstrapped::Bootstrapped;
use crate::{
    crust::CrustError,
    error::RoutingError,
    id::PublicId,
    messages::{MessageContent, SignedMessage},
    outbox::EventBox,
    peer_manager::{ConnectionInfoPreparedResult, Peer, PeerManager},
    routing_table::Authority,
    types::MessageId,
    xor_name::XorName,
    PrivConnectionInfo, PubConnectionInfo,
};
use log::LogLevel;
use safe_crypto::SharedSecretKey;
use std::collections::BTreeSet;

/// Common functionality for node states post-relocation.
pub trait Relocated: Bootstrapped {
    fn peer_mgr(&mut self) -> &mut PeerManager;
    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut EventBox);
    fn handle_connect_failure(&mut self, pub_id: PublicId, outbox: &mut EventBox);

    fn handle_connection_info_prepared(
        &mut self,
        result_token: u32,
        result: Result<PrivConnectionInfo, CrustError>,
    ) {
        let our_connection_info = match result {
            Err(err) => {
                error!(
                    "{} Failed to prepare connection info: {:?}. Retrying.",
                    self, err
                );
                let new_token = match self.peer_mgr().get_new_connection_info_token(result_token) {
                    Err(error) => {
                        debug!(
                            "{} Failed to prepare connection info, but no entry found in \
                             token map: {:?}",
                            self, error
                        );
                        return;
                    }
                    Ok(new_token) => new_token,
                };
                self.crust_service().prepare_connection_info(new_token);
                return;
            }
            Ok(connection_info) => connection_info,
        };

        let our_pub_info = our_connection_info.to_pub_connection_info();
        match self
            .peer_mgr()
            .connection_info_prepared(result_token, our_connection_info)
        {
            Err(error) => {
                // This usually means we have already connected.
                debug!(
                    "{} Prepared connection info, but no entry found in token map: {:?}",
                    self, error
                );
                return;
            }
            Ok(ConnectionInfoPreparedResult {
                pub_id,
                src,
                dst,
                infos,
            }) => match infos {
                None => {
                    debug!("{} Prepared connection info for {:?}.", self, pub_id);
                    self.send_connection_info(our_pub_info, pub_id, src, dst, None);
                }
                Some((our_info, their_info, msg_id)) => {
                    debug!(
                        "{} Trying to connect to {:?} as {:?}.",
                        self,
                        their_info.id(),
                        pub_id
                    );
                    self.send_connection_info(our_pub_info, pub_id, src, dst, Some(msg_id));
                    if let Err(error) = self.crust_service().connect(our_info, their_info) {
                        trace!("{} Unable to connect to {:?} - {:?}", self, pub_id, error);
                    }
                }
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_connection_info_request(
        &mut self,
        encrypted_connection_info: Vec<u8>,
        pub_id: PublicId,
        message_id: MessageId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        let shared_secret = self
            .full_id()
            .encrypting_private_key()
            .shared_secret(&pub_id.encrypting_public_key());
        let their_connection_info =
            self.decrypt_connection_info(&encrypted_connection_info, &shared_secret)?;
        if pub_id != their_connection_info.id() {
            debug!(
                "{} PublicId of the sender {} does not match the id mentioned in the message \
                 {}.",
                self,
                pub_id,
                their_connection_info.id()
            );
            return Err(RoutingError::InvalidPeer);
        }

        use crate::peer_manager::ConnectionInfoReceivedResult::*;
        match self.peer_mgr().connection_info_received(
            src,
            dst,
            their_connection_info,
            message_id,
            true,
        ) {
            Ok(Ready(our_info, their_info)) => {
                debug!(
                    "{} Already sent a connection info request to {}; resending \
                     our same details as a response.",
                    self, pub_id
                );
                self.send_connection_info(
                    our_info.to_pub_connection_info(),
                    pub_id,
                    dst,
                    src,
                    Some(message_id),
                );
                if let Err(error) = self.crust_service().connect(our_info, their_info) {
                    trace!("{} Unable to connect to {:?} - {:?}", self, src, error);
                }
            }
            Ok(Prepare(token)) => {
                self.crust_service().prepare_connection_info(token);
            }
            Ok(IsProxy) | Ok(IsClient) | Ok(IsJoiningNode) => {
                // TODO: we should not be getting conn info req from Proxy/JoiningNode
                log_or_panic!(
                    LogLevel::Error,
                    "{} Received ConnectionInfoRequest from peer {} \
                     with invalid state.",
                    self,
                    pub_id
                );

                if self.peer_mgr().is_connected(&pub_id) {
                    self.process_connection(pub_id, outbox);
                }
            }
            Ok(Waiting) | Ok(IsConnected) | Err(_) => (),
        }
        Ok(())
    }

    fn handle_connection_info_response(
        &mut self,
        encrypted_connection_info: Vec<u8>,
        public_id: PublicId,
        message_id: MessageId,
        src: XorName,
        dst: Authority<XorName>,
    ) -> Result<(), RoutingError> {
        if self.peer_mgr().get_peer(&public_id).is_none() {
            return Err(RoutingError::InvalidDestination);
        }

        let shared_secret = self
            .full_id()
            .encrypting_private_key()
            .shared_secret(&public_id.encrypting_public_key());
        let their_connection_info =
            self.decrypt_connection_info(&encrypted_connection_info, &shared_secret)?;
        if public_id != their_connection_info.id() {
            debug!(
                "{} PublicId of the sender {} does not match the id mentioned in the message \
                 {}.",
                self,
                public_id,
                their_connection_info.id()
            );
            return Err(RoutingError::InvalidPeer);
        }

        use crate::peer_manager::ConnectionInfoReceivedResult::*;
        match self.peer_mgr().connection_info_received(
            Authority::ManagedNode(src),
            dst,
            their_connection_info,
            message_id,
            false,
        ) {
            Ok(Ready(our_info, their_info)) => {
                trace!(
                    "{} Received connection info response. Trying to connect to {}.",
                    self,
                    public_id
                );
                if let Err(error) = self.crust_service().connect(our_info, their_info) {
                    trace!(
                        "{} Unable to connect to {:?} - {:?}",
                        self,
                        public_id,
                        error
                    );
                }
            }
            Ok(Prepare(_)) | Ok(IsProxy) | Ok(IsClient) | Ok(IsJoiningNode) => {
                debug!(
                    "{} Received connection info response from {} when we haven't \
                     sent a corresponding request",
                    self, public_id
                );
            }
            Ok(Waiting) | Ok(IsConnected) | Err(_) => (),
        }
        Ok(())
    }

    fn handle_connect_success(&mut self, pub_id: PublicId, outbox: &mut EventBox) {
        if self
            .peer_mgr()
            .get_peer(&pub_id)
            .map_or(false, Peer::is_routing)
        {
            warn!(
                "{} Received ConnectSuccess from {:?}, but node is already in routing \
                 state in peer_map.",
                self, pub_id
            );
            return;
        }

        self.peer_mgr().connected_to(&pub_id);
        debug!("{} Received ConnectSuccess from {}.", self, pub_id);
        self.process_connection(pub_id, outbox);
    }

    fn decrypt_connection_info(
        &self,
        encrypted_connection_info: &[u8],
        shared_secret: &SharedSecretKey,
    ) -> Result<PubConnectionInfo, RoutingError> {
        shared_secret
            .decrypt(encrypted_connection_info)
            .map_err(RoutingError::Crypto)
    }

    // If `msg_id` is `Some` this is sent as a response, otherwise as a request.
    fn send_connection_info(
        &mut self,
        our_pub_info: PubConnectionInfo,
        their_pub_id: PublicId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        msg_id: Option<MessageId>,
    ) {
        let shared_secret = self
            .full_id()
            .encrypting_private_key()
            .shared_secret(&their_pub_id.encrypting_public_key());
        let encrypted_conn_info = match shared_secret.encrypt(&our_pub_info) {
            Ok(encrypted_conn_info) => encrypted_conn_info,
            Err(err) => {
                debug!(
                    "{} Failed to serialise connection info for {:?}: {:?}.",
                    self, their_pub_id, err
                );
                return;
            }
        };
        let msg_content = if let Some(msg_id) = msg_id {
            MessageContent::ConnectionInfoResponse {
                encrypted_conn_info,
                pub_id: *self.full_id().public_id(),
                msg_id,
            }
        } else {
            MessageContent::ConnectionInfoRequest {
                encrypted_conn_info,
                pub_id: *self.full_id().public_id(),
                msg_id: MessageId::new(),
            }
        };

        if let Err(err) = self.send_routing_message(src, dst, msg_content) {
            debug!(
                "{} Failed to send connection info for {:?}: {:?}.",
                self, their_pub_id, err
            );
        }
    }

    /// Disconnects if the peer is not a proxy, client or routing table entry.
    fn disconnect_peer(&mut self, pub_id: &PublicId) {
        if self
            .peer_mgr()
            .get_peer(pub_id)
            .map_or(false, Peer::is_routing)
        {
            debug!("{} Not disconnecting routing table entry {}.", self, pub_id);
        } else if self.peer_mgr().is_proxy(pub_id) {
            debug!("{} Not disconnecting proxy node {}.", self, pub_id);
        } else if self.peer_mgr().is_joining_node(pub_id) {
            debug!("{} Not disconnecting joining node {:?}.", self, pub_id);
        } else {
            debug!(
                "{} Disconnecting {}. Calling crust::Service::disconnect.",
                self, pub_id
            );
            let _ = self.crust_service().disconnect(pub_id);
            let _ = self.peer_mgr().remove_peer(pub_id);
        }
    }

    // Filter, then convert the message to a `Hop` and serialise.
    // Send this byte string.
    fn send_signed_message_to_peer(
        &mut self,
        signed_msg: SignedMessage,
        target: &PublicId,
        route: u8,
        sent_to: BTreeSet<XorName>,
    ) -> Result<(), RoutingError> {
        if self.filter_outgoing_routing_msg(signed_msg.routing_message(), target, route) {
            return Ok(());
        }

        if self.crust_service().is_connected(target) {
            let priority = signed_msg.priority();
            let bytes = self.to_hop_bytes(signed_msg, route, sent_to)?;
            self.send_or_drop(target, bytes, priority);
        } else {
            trace!("{} Not connected to {:?}. Dropping peer.", self, target);
            self.disconnect_peer(target);
        }

        Ok(())
    }
}
