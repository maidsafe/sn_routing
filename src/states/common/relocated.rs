// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::bootstrapped::Bootstrapped;
use crate::{
    ack_manager::Ack,
    crust::CrustError,
    error::RoutingError,
    event::Event,
    id::PublicId,
    messages::MessageContent,
    outbox::EventBox,
    peer_manager::{ConnectionInfoPreparedResult, Peer, PeerManager, PeerState},
    routing_table::Authority,
    state_machine::Transition,
    types::MessageId,
    xor_name::XorName,
    PrivConnectionInfo, PubConnectionInfo,
};
use log::LogLevel;
use safe_crypto::SharedSecretKey;

/// Common functionality for node states post-relocation.
pub trait Relocated: Bootstrapped {
    fn peer_mgr(&self) -> &PeerManager;
    fn peer_mgr_mut(&mut self) -> &mut PeerManager;
    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut EventBox);
    fn is_peer_valid(&self, pub_id: &PublicId) -> bool;
    fn add_node_success(&mut self, pub_id: &PublicId);
    fn add_node_failure(&mut self, pub_id: &PublicId);
    fn send_event(&mut self, event: Event, outbox: &mut EventBox);

    fn handle_connection_info_prepared(
        &mut self,
        result_token: u32,
        result: Result<PrivConnectionInfo, CrustError>,
    ) -> Transition {
        let our_connection_info = match result {
            Err(err) => {
                error!(
                    "{} Failed to prepare connection info: {:?}. Retrying.",
                    self, err
                );
                let new_token = match self
                    .peer_mgr_mut()
                    .get_new_connection_info_token(result_token)
                {
                    Err(error) => {
                        debug!(
                            "{} Failed to prepare connection info, but no entry found in \
                             token map: {:?}",
                            self, error
                        );
                        return Transition::Stay;
                    }
                    Ok(new_token) => new_token,
                };
                self.crust_service().prepare_connection_info(new_token);
                return Transition::Stay;
            }
            Ok(connection_info) => connection_info,
        };

        let our_pub_info = our_connection_info.to_pub_connection_info();
        match self
            .peer_mgr_mut()
            .connection_info_prepared(result_token, our_connection_info)
        {
            Err(error) => {
                // This usually means we have already connected.
                debug!(
                    "{} Prepared connection info, but no entry found in token map: {:?}",
                    self, error
                );
                return Transition::Stay;
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

        Transition::Stay
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
        match self.peer_mgr_mut().connection_info_received(
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
        match self.peer_mgr_mut().connection_info_received(
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

    fn handle_connect_success(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        if self
            .peer_mgr()
            .get_peer(&pub_id)
            .map_or(false, Peer::is_node)
        {
            warn!(
                "{} Received ConnectSuccess from {:?}, but peer is already in Node \
                 state in peer manager.",
                self, pub_id
            );
            return Transition::Stay;
        }

        self.peer_mgr_mut().set_connected(&pub_id);
        debug!("{} Received ConnectSuccess from {}.", self, pub_id);
        self.process_connection(pub_id, outbox);

        Transition::Stay
    }

    fn handle_ack_response(&mut self, ack: Ack) {
        self.ack_mgr_mut().receive(ack)
    }

    fn log_connect_failure(&mut self, pub_id: &PublicId) {
        if let Some(&PeerState::CrustConnecting) = self.peer_mgr().get_peer(pub_id).map(Peer::state)
        {
            debug!("{} Failed to connect to peer {:?}.", self, pub_id);
        }
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

    // Note: This fn assumes `their_public_id` is a valid node in the network
    // Do not call this to respond to ConnectionInfo requests which are not yet validated.
    fn send_connection_info_request(
        &mut self,
        their_public_id: PublicId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        let their_name = *their_public_id.name();
        if !self.is_peer_valid(&their_public_id) {
            trace!(
                "{} Not sending ConnectionInfoRequest to Invalid peer {}.",
                self,
                their_name
            );
            return Err(RoutingError::InvalidPeer);
        }

        if self.peer_mgr().is_client(&their_public_id)
            || self.peer_mgr().is_joining_node(&their_public_id)
            || self.peer_mgr().is_proxy(&their_public_id)
        {
            // we use peer_name here instead of their_name since the peer can be
            // a joining node with its client name as far as proxy node is concerned
            self.process_connection(their_public_id, outbox);
            return Ok(());
        }

        if self.peer_mgr().is_connected(&their_public_id) {
            self.add_node(&their_public_id, outbox);
            return Ok(());
        }

        // This will insert the peer if peer is not in peer_mgr and flag them to `valid`
        if let Some(token) = self
            .peer_mgr_mut()
            .get_connection_token(src, dst, their_public_id)
        {
            self.crust_service().prepare_connection_info(token);
            return Ok(());
        }

        let log_ident = format!("{}", self);
        let our_pub_info = match self.peer_mgr().get_peer(&their_public_id).map(Peer::state) {
            Some(PeerState::ConnectionInfoReady(our_priv_info)) => {
                our_priv_info.to_pub_connection_info()
            }
            state => {
                trace!(
                    "{} Not sending connection info request to {:?}. State: {:?}",
                    log_ident,
                    their_name,
                    state
                );
                return Ok(());
            }
        };

        trace!(
            "{} Resending connection info request to {:?}",
            self,
            their_name
        );
        self.send_connection_info(our_pub_info, their_public_id, src, dst, None);
        Ok(())
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
            .map_or(false, Peer::is_node)
        {
            debug!("{} Not disconnecting node {}.", self, pub_id);
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
            let _ = self.peer_mgr_mut().remove_peer(pub_id);
        }
    }

    fn add_node(&mut self, pub_id: &PublicId, outbox: &mut EventBox) {
        match self.peer_mgr_mut().set_node(pub_id) {
            Ok(true) => {
                info!("{} - Added peer {} as node.", self, pub_id);
                self.send_event(Event::NodeAdded(*pub_id.name()), outbox);
                self.add_node_success(pub_id);
            }
            Ok(false) => {}
            Err(error) => {
                debug!("{} Peer {:?} was not updated: {:?}", self, pub_id, error);
                self.add_node_failure(pub_id);
                return;
            }
        }
    }
}
