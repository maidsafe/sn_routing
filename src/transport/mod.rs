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
    quic_p2p::{EventSenders, Peer, QuicP2p, QuicP2pError, Token},
    time::Duration,
    timer::Timer,
    TransportConfig,
};
use bytes::Bytes;
use hex_fmt::HexFmt;
use std::{collections::HashMap, net::SocketAddr};

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
    pub fn new(event_tx: EventSenders, config: TransportConfig) -> Result<Self, QuicP2pError> {
        {
            let quic_p2p = QuicP2p::with_config(event_tx, Some(config), Default::default(), false)?;

            Ok(Transport {
                quic_p2p,
                cache: Default::default(),
                next_msg_token: 0,
                scheduled_messages: Default::default(),
            })
        }
    }

    pub fn bootstrap(&mut self) {
        self.quic_p2p.bootstrap()
    }

    pub fn send_message_to_targets(
        &mut self,
        conn_infos: &[SocketAddr],
        delivery_group_size: usize,
        msg: Bytes,
    ) {
        if conn_infos.len() < delivery_group_size {
            warn!(
                "Less than delivery_group_size valid targets! delivery_group_size = {}; targets = {:?}; msg = {:?}",
                delivery_group_size,
                conn_infos,
                HexFmt(&msg)
            );
        }

        let token = self.next_msg_token();

        trace!(
            "Sending message with token {} to {:?}",
            token,
            &conn_infos[..delivery_group_size.min(conn_infos.len())]
        );

        // initially only send to delivery_group_size targets
        for addr in conn_infos.iter().take(delivery_group_size) {
            // NetworkBytes is refcounted and cheap to clone.
            self.send_now(*addr, msg.clone(), token);
        }

        self.cache
            .insert_message(token, conn_infos, delivery_group_size);
    }

    pub fn send_message_to_client(&mut self, target: SocketAddr, msg: Bytes, token: Token) {
        let client = Peer::Client(target);
        self.quic_p2p.send(client, msg, token);
    }

    pub fn target_succeeded(&mut self, token: Token, target: SocketAddr) {
        self.cache.target_succeeded(token, target)
    }

    pub fn target_failed(
        &mut self,
        msg: Bytes,
        msg_token: Token,
        failed_target: SocketAddr,
        timer: &Timer,
    ) -> PeerStatus {
        match self.cache.target_failed(msg_token, failed_target) {
            Resend::Now(next_target) => {
                trace!(
                    "Sending message with token {} to {} failed - resending to {} now",
                    msg_token,
                    failed_target,
                    next_target
                );

                self.send_now(next_target, msg, msg_token);
                PeerStatus::Normal
            }
            Resend::Later(next_target, delay) => {
                trace!(
                    "Sending message with token {} to {} failed - resending to {} in {:?}",
                    msg_token,
                    failed_target,
                    next_target,
                    delay
                );

                self.send_later(next_target, msg, msg_token, timer, delay);
                PeerStatus::Normal
            }
            Resend::Never => {
                trace!(
                    "Sending message with token {} to {} failed too many times - giving up.",
                    msg_token,
                    failed_target,
                );

                PeerStatus::Lost
            }
        }
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

    fn next_msg_token(&mut self) -> Token {
        self.next_msg_token = self.next_msg_token.wrapping_add(1);
        self.next_msg_token
    }

    fn send_now(&mut self, target: SocketAddr, content: Bytes, token: Token) {
        self.quic_p2p.send(Peer::Node(target), content, token)
    }

    fn send_later(
        &mut self,
        target: SocketAddr,
        content: Bytes,
        token: Token,
        timer: &Timer,
        delay: Duration,
    ) {
        let timer_token = timer.schedule(delay);
        let _ = self.scheduled_messages.insert(
            timer_token,
            ScheduledMessage {
                content,
                token,
                target,
            },
        );
    }
}

struct ScheduledMessage {
    content: Bytes,
    token: Token,
    target: SocketAddr,
}

#[derive(Debug)]
pub enum PeerStatus {
    Normal,
    Lost,
}
