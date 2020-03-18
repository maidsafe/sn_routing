// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod base;

pub use self::base::Base;
use crate::{
    id::FullId,
    location::DstLocation,
    message_filter::MessageFilter,
    messages::{Message, Variant},
    network_service::NetworkService,
    rng::MainRng,
    time::Duration,
    timer::Timer,
    xor_space::XorName,
};
use bytes::Bytes;
use std::{net::SocketAddr, slice};

/// Delay after which a bounced message is resent.
pub const BOUNCE_RESEND_DELAY: Duration = Duration::from_secs(1);

/// Struct that contains data common to all states.
pub struct Core {
    pub full_id: FullId,
    pub network_service: NetworkService,
    pub msg_filter: MessageFilter,
    pub timer: Timer,
    pub rng: MainRng,
}

impl Core {
    pub fn name(&self) -> &XorName {
        self.full_id.public_id().name()
    }

    pub fn send_message_to_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        dg_size: usize,
        msg: Bytes,
    ) {
        self.network_service
            .send_message_to_targets(conn_infos, dg_size, msg)
    }

    pub fn send_message_to_target_later(
        &mut self,
        dst: &SocketAddr,
        message: Bytes,
        delay: Duration,
    ) {
        let timer_token = self.timer.schedule(delay);
        self.network_service
            .send_message_to_target_later(dst, message, timer_token)
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
}
