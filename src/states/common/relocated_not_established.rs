// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Relocated;
use crate::{
    error::{BootstrapResponseError, RoutingError},
    event::Event,
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
            Some(PeerState::Connected) | Some(PeerState::Proxy) => return Ok(()),
            Some(PeerState::Connecting) => {
                if let DirectMessage::ConnectionResponse = msg {
                    return Ok(());
                }
            }
            _ => (),
        }

        debug!(
            "{} Illegitimate direct message {:?} from {:?}.",
            self, msg, pub_id
        );
        Err(RoutingError::InvalidStateForOperation)
    }

    fn handle_routing_message(
        &mut self,
        msg: RoutingMessage,
        outbox: &mut EventBox,
    ) -> Result<Transition, RoutingError> {
        use crate::{messages::MessageContent::*, routing_table::Authority::*};

        let src_name = msg.src.name();

        match msg {
            RoutingMessage {
                content:
                    ConnectionRequest {
                        encrypted_conn_info,
                        pub_id,
                        msg_id,
                    },
                src: ManagedNode(_),
                dst: ManagedNode(_),
            } => {
                if self.our_prefix().matches(&src_name) {
                    self.handle_connection_request(
                        &encrypted_conn_info,
                        pub_id,
                        msg.src,
                        msg.dst,
                        outbox,
                    )
                } else {
                    self.add_message_to_backlog(RoutingMessage {
                        content: ConnectionRequest {
                            encrypted_conn_info,
                            pub_id,
                            msg_id,
                        },
                        ..msg
                    });
                    Ok(Transition::Stay)
                }
            }
            _ => {
                self.add_message_to_backlog(msg);
                Ok(Transition::Stay)
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

    fn handle_bootstrap_request(&mut self, pub_id: PublicId) {
        debug!(
            "{} - Client {:?} rejected: We are not an established node yet.",
            self, pub_id
        );

        self.send_direct_message(
            &pub_id,
            DirectMessage::BootstrapResponse(Err(BootstrapResponseError::NotApproved)),
        );
        self.disconnect_peer(&pub_id);
    }

    fn handle_peer_disconnected(&mut self, pub_id: PublicId, outbox: &mut EventBox) -> Transition {
        debug!("{} - Disconnected from {}", self, pub_id);

        let was_proxy = self.peer_mgr().is_proxy(&pub_id);

        if self.peer_mgr_mut().remove_peer(&pub_id) {
            self.send_event(Event::NodeLost(*pub_id.name()), outbox);
        }

        if was_proxy {
            debug!("{} - Lost connection to proxy {}.", self, pub_id);
            outbox.send_event(Event::Terminated);
            Transition::Terminate
        } else {
            Transition::Stay
        }
    }
}
