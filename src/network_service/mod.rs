// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod sending_targets_cache;

use crate::{
    quic_p2p::{Builder, Error},
    utils::LogIdent,
    NetworkBytes, NetworkConfig, NetworkEvent, QuicP2p,
};
use crossbeam_channel::Sender;
use std::net::SocketAddr;

use sending_targets_cache::SendingTargetsCache;

/// Struct that handles network operations: sending and receiving messages, as well as resending on
/// failure.
pub struct NetworkService {
    quic_p2p: QuicP2p,
    cache: SendingTargetsCache,
    next_msg_id: u64,
}

impl NetworkService {
    pub fn service(&self) -> &QuicP2p {
        &self.quic_p2p
    }

    pub fn service_mut(&mut self) -> &mut QuicP2p {
        &mut self.quic_p2p
    }

    pub fn next_msg_id(&mut self) -> u64 {
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        self.next_msg_id
    }

    pub fn targets_cache_mut(&mut self) -> &mut SendingTargetsCache {
        &mut self.cache
    }

    pub fn send_message_to_next_target(
        &mut self,
        msg: NetworkBytes,
        msg_id: u64,
        failed_tgt: SocketAddr,
        log_ident: LogIdent,
    ) {
        if let Some(tgt) = self.cache.target_failed(msg_id, failed_tgt) {
            info!(
                "{} Sending of message ID {} failed; resending...",
                log_ident, msg_id
            );
            self.quic_p2p.send(tgt, msg, msg_id);
        }
    }
}

pub struct NetworkBuilder {
    quic_p2p: Builder,
}

impl NetworkBuilder {
    pub fn new(event_tx: Sender<NetworkEvent>) -> Self {
        Self {
            quic_p2p: Builder::new(event_tx),
        }
    }

    pub fn with_config(self, config: NetworkConfig) -> Self {
        Self {
            quic_p2p: self.quic_p2p.with_config(config),
        }
    }

    pub fn build(self) -> Result<NetworkService, Error> {
        Ok(NetworkService {
            quic_p2p: self.quic_p2p.build()?,
            cache: Default::default(),
            next_msg_id: 0,
        })
    }
}
