// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    id::{FullId, PublicId},
    location::DstLocation,
    message_filter::MessageFilter,
    messages::{Message, Variant},
    quic_p2p::Token,
    rng::MainRng,
    time::Duration,
    timer::Timer,
    transport::{PeerStatus, Transport},
    xor_space::XorName,
};
use bytes::Bytes;
use std::{net::SocketAddr, slice};

// Core components of the node.
pub struct Core {
    pub full_id: FullId,
    pub transport: Transport,
    pub msg_filter: MessageFilter,
    pub timer: Timer,
    pub rng: MainRng,
}

impl Core {
    pub fn id(&self) -> &PublicId {
        self.full_id.public_id()
    }

    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    pub fn send_message_to_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        dg_size: usize,
        msg: Bytes,
    ) {
        self.transport
            .send_message_to_targets(conn_infos, dg_size, msg)
    }

    pub fn send_message_to_target_later(
        &mut self,
        dst: &SocketAddr,
        message: Bytes,
        delay: Duration,
    ) {
        self.transport
            .send_message_to_target_later(dst, message, &self.timer, delay)
    }

    pub fn send_direct_message(&mut self, recipient: &SocketAddr, variant: Variant) {
        let message = match Message::single_src(&self.full_id, DstLocation::Direct, variant) {
            Ok(message) => message,
            Err(error) => {
                error!("Failed to create message: {:?}", error);
                return;
            }
        };

        let bytes = match message.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                error!("Failed to serialize message {:?}: {:?}", message, error);
                return;
            }
        };

        self.send_message_to_targets(slice::from_ref(recipient), 1, bytes)
    }

    pub fn handle_unsent_message(
        &mut self,
        addr: SocketAddr,
        msg: Bytes,
        msg_token: Token,
    ) -> PeerStatus {
        self.transport
            .target_failed(msg, msg_token, addr, &self.timer)
    }
}
