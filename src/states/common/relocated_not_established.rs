// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Relocated;
use crate::{
    error::RoutingError,
    id::PublicId,
    messages::{DirectMessage, RoutingMessage},
    outbox::EventBox,
    peer_manager::{Peer, PeerState},
    routing_table::Prefix,
    state_machine::Transition,
    xor_name::XorName,
};

pub trait RelocatedNotEstablished: Relocated {
    fn our_prefix(&self) -> &Prefix<XorName>;
    fn push_message_to_backlog(&mut self, msg: RoutingMessage);

    fn check_direct_message_sender(
        &self,
        msg: &DirectMessage,
        pub_id: &PublicId,
    ) -> Result<(), RoutingError> {
        match self.peer_mgr().get_peer(pub_id).map(Peer::state) {
            Some(&PeerState::Connected) | Some(&PeerState::Proxy) => Ok(()),
            _ => {
                debug!(
                    "{} Illegitimate direct message {:?} from {:?}.",
                    self, msg, pub_id
                );
                Err(RoutingError::InvalidStateForOperation)
            }
        }
    }

    fn handle_routing_message(
        &mut self,
        msg: RoutingMessage,
        outbox: &mut EventBox,
    ) -> Result<(), RoutingError> {
        use crate::{messages::MessageContent::*, routing_table::Authority::*};

        let src_name = msg.src.name();

        match msg {
            RoutingMessage {
                content:
                    ConnectionInfoRequest {
                        encrypted_conn_info,
                        pub_id,
                        msg_id,
                    },
                src: ManagedNode(_),
                dst: ManagedNode(_),
            } => {
                if self.our_prefix().matches(&src_name) {
                    self.handle_connection_info_request(
                        encrypted_conn_info,
                        pub_id,
                        msg_id,
                        msg.src,
                        msg.dst,
                        outbox,
                    )
                } else {
                    self.add_message_to_backlog(RoutingMessage {
                        content: ConnectionInfoRequest {
                            encrypted_conn_info,
                            pub_id,
                            msg_id,
                        },
                        ..msg
                    });
                    Ok(())
                }
            }
            RoutingMessage {
                content:
                    ConnectionInfoResponse {
                        encrypted_conn_info,
                        pub_id,
                        msg_id,
                    },
                src: ManagedNode(src_name),
                dst: Client { .. },
            } => self.handle_connection_info_response(
                encrypted_conn_info,
                pub_id,
                msg_id,
                src_name,
                msg.dst,
            ),
            RoutingMessage {
                content: Ack(ack, _),
                ..
            } => {
                self.handle_ack_response(ack);
                Ok(())
            }
            _ => {
                self.add_message_to_backlog(msg);
                Ok(())
            }
        }
    }

    // Backlog the message to be processed once we are established.
    fn add_message_to_backlog(&mut self, msg: RoutingMessage) {
        trace!(
            "{} Not established yet. Delaying message handling: {:?}",
            self,
            msg
        );
        self.push_message_to_backlog(msg);
    }

    fn handle_connect_failure(&mut self, pub_id: PublicId) -> Transition {
        self.log_connect_failure(&pub_id);
        let _ = self.dropped_peer(&pub_id);
        Transition::Stay
    }

    fn dropped_peer(&mut self, pub_id: &PublicId) -> bool {
        let was_proxy = self.peer_mgr().is_proxy(pub_id);
        let _ = self.peer_mgr_mut().remove_peer(pub_id);
        let _ = self.remove_from_notified_nodes(pub_id);

        if was_proxy {
            debug!("{} Lost connection to proxy {}.", self, pub_id);
            false
        } else {
            true
        }
    }
}
