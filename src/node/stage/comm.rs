// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::Result,
    id::FullId,
    location::DstLocation,
    messages::{Message, Variant},
};
use bytes::Bytes;
use futures::{
    lock::Mutex,
    stream::{FuturesUnordered, StreamExt},
};
use itertools::Itertools;
use lru_time_cache::LruCache;
use qp2p::{Config, Connection, Endpoint, IncomingConnections, QuicP2p};
use std::{net::SocketAddr, slice, sync::Arc, time::Duration};
use tokio::time;

// Number of Connections to maintain in the cache
const CONNECTIONS_CACHE_SIZE: usize = 1024;

/// Maximal number of resend attempts to the same target.
pub const RESEND_MAX_ATTEMPTS: u8 = 3;
/// Delay before attempting to resend a previously failed message.
pub const RESEND_DELAY: Duration = Duration::from_secs(10);

// Communication component of the node to interact with other nodes.
#[derive(Clone)]
pub(crate) struct Comm {
    inner: Arc<Inner>,
}

impl Comm {
    pub async fn new(transport_config: Config) -> Result<Self> {
        let quic_p2p = QuicP2p::with_config(Some(transport_config), Default::default(), true)?;

        // Don't bootstrap, just create an endpoint where to listen to
        // the incoming messages from other nodes.
        let endpoint = quic_p2p.new_endpoint()?;
        let node_conns = Mutex::new(LruCache::with_capacity(CONNECTIONS_CACHE_SIZE));

        Ok(Self {
            inner: Arc::new(Inner {
                _quic_p2p: quic_p2p,
                endpoint,
                node_conns,
            }),
        })
    }

    pub async fn from_bootstrapping(transport_config: Config) -> Result<(Self, SocketAddr)> {
        let mut quic_p2p = QuicP2p::with_config(Some(transport_config), Default::default(), true)?;

        // Bootstrap to the network returning the connection to a node.
        let (endpoint, conn) = quic_p2p.bootstrap().await?;
        let addr = conn.remote_address();

        let mut node_conns = LruCache::with_capacity(CONNECTIONS_CACHE_SIZE);
        let _ = node_conns.insert(addr, Arc::new(conn));
        let node_conns = Mutex::new(node_conns);

        Ok((
            Self {
                inner: Arc::new(Inner {
                    _quic_p2p: quic_p2p,
                    endpoint,
                    node_conns,
                }),
            },
            addr,
        ))
    }

    /// Starts listening for connections returning a stream where to read them from.
    pub fn listen(&self) -> Result<IncomingConnections> {
        Ok(self.inner.endpoint.listen()?)
    }

    pub fn our_connection_info(&self) -> Result<SocketAddr> {
        self.inner.endpoint.our_endpoint().map_err(|err| {
            debug!("Failed to retrieve our connection info: {:?}", err);
            err.into()
        })
    }

    pub async fn send_message_to_targets(
        &self,
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        msg: Bytes,
    ) -> Result<()> {
        if recipients.len() < delivery_group_size {
            warn!(
                "Less than delivery_group_size valid recipients - delivery_group_size: {}, recipients: {:?}",
                delivery_group_size,
                recipients,
            );
        }

        let mut state = SendState::new(recipients, delivery_group_size);
        let mut tasks = FuturesUnordered::new();

        loop {
            while let Some((addr, failed)) = state.next() {
                trace!("Sending message to {}", addr);
                tasks.push(self.inner.send_with_delay(addr, msg.clone(), failed));
            }

            if let Some((addr, result)) = tasks.next().await {
                if result.is_ok() {
                    trace!("Sending message to {} succeeded", addr);
                    state.success(&addr);
                } else {
                    trace!("Sending message to {} failed", addr);
                    state.failure(&addr);
                }
            } else {
                break;
            }
        }

        trace!(
            "Sending message finished (failed recipients: [{}])",
            state.failed().format(", ")
        );

        Ok(())
    }

    pub async fn send_message_to_target(&self, recipient: &SocketAddr, msg: Bytes) -> Result<()> {
        self.send_message_to_targets(slice::from_ref(recipient), 1, msg)
            .await
    }

    pub async fn send_direct_message(
        &self,
        src_id: &FullId,
        recipient: &SocketAddr,
        variant: Variant,
    ) -> Result<()> {
        let message = Message::single_src(src_id, DstLocation::Direct, variant, None, None)?;
        self.send_message_to_target(recipient, message.to_bytes())
            .await
    }
}

struct Inner {
    _quic_p2p: QuicP2p,
    endpoint: Endpoint,
    node_conns: Mutex<LruCache<SocketAddr, Arc<Connection>>>,
}

impl Inner {
    async fn send(&self, recipient: &SocketAddr, msg: Bytes) -> Result<()> {
        // Cache the Connection to the node or obtain the already cached one
        // Note: not using the entry API to avoid holding the mutex longer than necessary.
        let conn = self.node_conns.lock().await.get(recipient).cloned();
        let conn = if let Some(conn) = conn {
            conn
        } else {
            let conn = self.endpoint.connect_to(recipient).await?;
            let conn = Arc::new(conn);
            let _ = self
                .node_conns
                .lock()
                .await
                .insert(*recipient, Arc::clone(&conn));

            conn
        };

        conn.send_uni(msg).await?;

        Ok(())
    }

    async fn send_with_delay(
        &self,
        recipient: SocketAddr,
        msg: Bytes,
        delay: bool,
    ) -> (SocketAddr, Result<()>) {
        if delay {
            time::delay_for(RESEND_DELAY).await;
        }

        let result = self.send(&recipient, msg).await;
        (recipient, result)
    }
}

struct SendState {
    recipients: Vec<Recipient>,
    remaining: usize,
}

struct Recipient {
    addr: SocketAddr,
    sending: bool,
    attempt: u8,
}

impl SendState {
    fn new(recipients: &[SocketAddr], delivery_group_size: usize) -> Self {
        Self {
            recipients: recipients
                .iter()
                .map(|addr| Recipient {
                    addr: *addr,
                    sending: false,
                    attempt: 0,
                })
                .collect(),
            remaining: delivery_group_size,
        }
    }

    // Returns the next recipient to sent to.
    fn next(&mut self) -> Option<(SocketAddr, bool)> {
        let active = self
            .recipients
            .iter()
            .filter(|recipient| recipient.sending)
            .count();

        if active >= self.remaining {
            return None;
        }

        let recipient = self
            .recipients
            .iter_mut()
            .filter(|recipient| !recipient.sending && recipient.attempt < RESEND_MAX_ATTEMPTS)
            .min_by_key(|recipient| recipient.attempt)?;

        recipient.attempt += 1;
        recipient.sending = true;

        Some((recipient.addr, recipient.attempt > 1))
    }

    // Marks the recipient as failed.
    fn failure(&mut self, addr: &SocketAddr) {
        if let Some(recipient) = self
            .recipients
            .iter_mut()
            .find(|recipient| recipient.addr == *addr)
        {
            recipient.sending = false;
        }
    }

    // Marks the recipient as successful.
    fn success(&mut self, addr: &SocketAddr) {
        if let Some(index) = self
            .recipients
            .iter()
            .position(|recipient| recipient.addr == *addr)
        {
            let _ = self.recipients.swap_remove(index);
            self.remaining -= 1;
        }
    }

    // // Did we successfuly send to the required number of recipients?
    // fn complete(&self) -> bool {
    //     self.remaining == 0
    // }

    // Returns all failed recipients.
    fn failed(&self) -> impl Iterator<Item = &SocketAddr> {
        self.recipients
            .iter()
            .filter(|recipient| !recipient.sending && recipient.attempt >= RESEND_MAX_ATTEMPTS)
            .map(|recipient| &recipient.addr)
    }
}
