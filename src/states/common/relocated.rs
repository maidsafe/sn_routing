// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{base::Base, bootstrapped::Bootstrapped};
use crate::{
    ack_manager::Ack,
    error::RoutingError,
    event::Event,
    id::PublicId,
    messages::{DirectMessage, MessageContent},
    outbox::EventBox,
    peer_manager::{Peer, PeerManager},
    quic_p2p::NodeInfo,
    routing_table::Authority,
    state_machine::Transition,
    types::MessageId,
    xor_name::XorName,
    ConnectionInfo,
};

/// Common functionality for node states post-relocation.
pub trait Relocated: Bootstrapped {
    fn peer_mgr(&self) -> &PeerManager;
    fn peer_mgr_mut(&mut self) -> &mut PeerManager;
    fn process_connection(&mut self, pub_id: PublicId, outbox: &mut EventBox);
    fn is_peer_valid(&self, pub_id: &PublicId) -> bool;
    fn add_node_success(&mut self, pub_id: &PublicId);
    fn add_node_failure(&mut self, pub_id: &PublicId);
    fn send_event(&mut self, event: Event, outbox: &mut EventBox);

    fn send_connection_request(
        &mut self,
        their_pub_id: PublicId,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        if self.peer_mgr().is_connected(&their_pub_id) {
            debug!(
                "{} - Not sending our connection info to {:?} - already connected.",
                self, their_pub_id
            );

            self.process_connection(their_pub_id, outbox);
            return Ok(());
        } else if self.peer_mgr().is_connecting(&their_pub_id) {
            debug!(
                "{} - Not sending our connection info to {:?} - already sent or received.",
                self, their_pub_id
            );
            return Ok(());
        } else {
            self.peer_mgr_mut().set_connecting(their_pub_id);
        }

        let our_conn_info = self.our_connection_info()?;
        let shared_secret = self
            .full_id()
            .encrypting_private_key()
            .shared_secret(&their_pub_id.encrypting_public_key());
        let encrypted_conn_info = shared_secret.encrypt(&our_conn_info).map_err(|err| {
            debug!(
                "{} - Failed to serialise our connection info for {:?}: {:?}.",
                self, their_pub_id, err
            );
            err
        })?;

        let content = MessageContent::ConnectionRequest {
            encrypted_conn_info,
            pub_id: *self.full_id().public_id(),
            msg_id: MessageId::new(),
        };

        debug!(
            "{} - Sending our connection info to {:?}.",
            self, their_pub_id
        );

        self.send_routing_message(src, dst, content).map_err(|err| {
            debug!(
                "{} - Failed to send our connection info for {:?}: {:?}.",
                self, their_pub_id, err
            );
            err
        })
    }

    fn handle_connection_request(
        &mut self,
        encrypted_their_conn_info: &[u8],
        their_pub_id: PublicId,
        _src: Authority<XorName>,
        _dst: Authority<XorName>,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        let shared_secret = self
            .full_id()
            .encrypting_private_key()
            .shared_secret(&their_pub_id.encrypting_public_key());
        let their_conn_info: NodeInfo = shared_secret
            .decrypt(encrypted_their_conn_info)
            .map_err(RoutingError::Crypto)?;

        debug!(
            "{} - Received connection info from {:?}.",
            self, their_pub_id
        );

        self.peer_mgr_mut().set_connecting(their_pub_id);

        let transition = match self
            .peer_map_mut()
            .handle_connection_request(their_pub_id, their_conn_info.clone())
        {
            Ok(()) => Base::handle_peer_connected(
                self,
                their_pub_id,
                ConnectionInfo::Node {
                    node_info: their_conn_info,
                },
                outbox,
            ),
            _ => Transition::Stay,
        };

        self.send_direct_message(&their_pub_id, DirectMessage::ConnectionResponse);

        Ok(transition)
    }

    fn handle_ack_response(&mut self, ack: Ack) {
        self.ack_mgr_mut().receive(ack)
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
        } else if self.peer_mgr().is_or_was_joining_node(pub_id) {
            debug!("{} Not disconnecting joining node {:?}.", self, pub_id);
        } else {
            debug!("{} Disconnecting {}.", self, pub_id);

            if let Some(peer) = self.peer_map_mut().remove(pub_id) {
                self.network_service_mut().disconnect_from(peer.peer_addr());
            }

            let _ = self.peer_mgr_mut().remove_peer(pub_id);
        }
    }

    fn add_node(&mut self, pub_id: &PublicId, outbox: &mut EventBox) {
        let log_ident = self.log_ident();
        match self.peer_mgr_mut().set_node(pub_id, &log_ident) {
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
