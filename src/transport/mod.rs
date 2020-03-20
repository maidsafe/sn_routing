// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod sending_targets_cache;

pub use sending_targets_cache::{Resend, RESEND_DELAY, RESEND_MAX_ATTEMPTS};

use crate::{
    quic_p2p::{Builder, EventSenders, Peer, QuicP2p, QuicP2pError, Token},
    NetworkConfig,
};
use bytes::Bytes;
use hex_fmt::HexFmt;
use std::{collections::HashMap, net::SocketAddr, slice};

use sending_targets_cache::SendingTargetsCache;

/// Struct that handles network operations: sending and receiving messages, as well as resending on
/// failure.
pub struct Transport {
    quic_p2p: QuicP2p,
    cache: SendingTargetsCache,
    next_msg_token: Token,
    scheduled_messages: HashMap<u64, ScheduledMessage>,
}

impl Transport {
    pub fn service_mut(&mut self) -> &mut QuicP2p {
        &mut self.quic_p2p
    }

    pub fn next_msg_token(&mut self) -> Token {
        self.next_msg_token = self.next_msg_token.wrapping_add(1);
        self.next_msg_token
    }

    pub fn targets_cache_mut(&mut self) -> &mut SendingTargetsCache {
        &mut self.cache
    }

    pub fn send_message_to_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        dg_size: usize,
        msg: Bytes,
    ) {
        if conn_infos.len() < dg_size {
            warn!(
                "Less than dg_size valid targets! dg_size = {}; targets = {:?}; msg = {:?}",
                dg_size,
                conn_infos,
                HexFmt(&msg)
            );
        }

        let token = self.next_msg_token();

        trace!(
            "Sending message ID {} to {:?}",
            token,
            &conn_infos[..dg_size.min(conn_infos.len())]
        );

        // initially only send to dg_size targets
        for addr in conn_infos.iter().take(dg_size) {
            // NetworkBytes is refcounted and cheap to clone.
            self.send_now(*addr, msg.clone(), token);
        }

        self.cache.insert_message(token, conn_infos, dg_size);
    }

    pub fn send_message_to_target_later(
        &mut self,
        target: &SocketAddr,
        content: Bytes,
        timer_token: u64,
    ) {
        let token = self.next_msg_token();
        self.send_later(*target, content, token, timer_token);
        self.cache.insert_message(token, slice::from_ref(target), 1);
    }

    pub fn target_failed(&mut self, msg_token: Token, failed_target: SocketAddr) -> Resend {
        self.cache.target_failed(msg_token, failed_target)
    }

    pub fn send_now(&mut self, target: SocketAddr, content: Bytes, token: Token) {
        self.quic_p2p.send(Peer::Node(target), content, token)
    }

    pub fn send_later(
        &mut self,
        target: SocketAddr,
        content: Bytes,
        token: Token,
        timer_token: u64,
    ) {
        let _ = self.scheduled_messages.insert(
            timer_token,
            ScheduledMessage {
                content,
                token,
                target,
            },
        );
    }

    pub fn our_connection_info(&mut self) -> Result<SocketAddr, QuicP2pError> {
        self.quic_p2p.our_connection_info()
    }

    pub fn disconnect(&mut self, addr: SocketAddr) {
        self.quic_p2p.disconnect_from(addr)
    }

    pub fn handle_timeout(&mut self, timer_token: u64) -> bool {
        if let Some(msg) = self.scheduled_messages.remove(&timer_token) {
            self.quic_p2p
                .send(Peer::Node(msg.target), msg.content, msg.token);
            true
        } else {
            false
        }
    }
}

pub struct TransportBuilder {
    quic_p2p: Builder,
}

impl TransportBuilder {
    pub fn new(event_tx: EventSenders) -> Self {
        Self {
            quic_p2p: Builder::new(event_tx),
        }
    }

    pub fn with_config(self, config: NetworkConfig) -> Self {
        Self {
            quic_p2p: self.quic_p2p.with_config(config),
        }
    }

    pub fn build(self) -> Result<Transport, QuicP2pError> {
        Ok(Transport {
            quic_p2p: self.quic_p2p.build()?,
            cache: Default::default(),
            next_msg_token: 0,
            scheduled_messages: Default::default(),
        })
    }
}

struct ScheduledMessage {
    content: Bytes,
    token: Token,
    target: SocketAddr,
}
