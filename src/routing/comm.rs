// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::{Error, Result};
use bytes::Bytes;
use err_derive::Error;
use futures::{
    lock::Mutex,
    stream::{FuturesUnordered, StreamExt},
};
use lru_time_cache::LruCache;
use qp2p::{Connection, Endpoint, IncomingConnections, QuicP2p};
use std::{net::SocketAddr, sync::Arc};

// Number of Connections to maintain in the cache
const CONNECTIONS_CACHE_SIZE: usize = 1024;

/// Maximal number of resend attempts to the same target.
pub const RESEND_MAX_ATTEMPTS: u8 = 3;

// Communication component of the node to interact with other nodes.
pub(crate) struct Comm {
    _quic_p2p: QuicP2p,
    endpoint: Endpoint,
    node_conns: Mutex<LruCache<SocketAddr, Arc<Connection>>>,
}

impl Comm {
    pub fn new(transport_config: qp2p::Config) -> Result<Self> {
        let quic_p2p = QuicP2p::with_config(Some(transport_config), Default::default(), true)?;

        // Don't bootstrap, just create an endpoint where to listen to
        // the incoming messages from other nodes.
        let endpoint = quic_p2p.new_endpoint()?;
        let node_conns = Mutex::new(LruCache::with_capacity(CONNECTIONS_CACHE_SIZE));

        Ok(Self {
            _quic_p2p: quic_p2p,
            endpoint,
            node_conns,
        })
    }

    pub async fn from_bootstrapping(transport_config: qp2p::Config) -> Result<(Self, SocketAddr)> {
        let quic_p2p = QuicP2p::with_config(Some(transport_config), Default::default(), true)?;

        // Bootstrap to the network returning the connection to a node.
        let (endpoint, conn) = quic_p2p.bootstrap().await?;
        let addr = conn.remote_address();

        let mut node_conns = LruCache::with_capacity(CONNECTIONS_CACHE_SIZE);
        let _ = node_conns.insert(addr, Arc::new(conn));
        let node_conns = Mutex::new(node_conns);

        Ok((
            Self {
                _quic_p2p: quic_p2p,
                endpoint,
                node_conns,
            },
            addr,
        ))
    }

    /// Starts listening for connections returning a stream where to read them from.
    pub fn listen(&self) -> Result<IncomingConnections> {
        Ok(self.endpoint.listen()?)
    }

    pub fn our_connection_info(&self) -> Result<SocketAddr> {
        self.endpoint.our_endpoint().map_err(|err| {
            debug!("Failed to retrieve our connection info: {:?}", err);
            err.into()
        })
    }

    /// Sends a message to multiple recipients. Attempts to send to `delivery_group_size`
    /// recipients out of the `recipients` list. If a send fails, attempts to send to the next peer
    /// until `delivery_goup_size` successful sends complete or there are no more recipients to
    /// try. Each recipient will be attempted at most `RESEND_MAX_ATTEMPTS` times. If it fails all
    /// the attempts, it is considered as lost.
    ///
    /// Returns `Ok` if all of `delivery_group_size` sends succeeded and `Err` if less that
    /// `delivery_group_size` succeeded. The returned error contains a list of all the recipients
    /// that failed all their respective attempts.
    pub async fn send_message_to_targets(
        &self,
        recipients: &[SocketAddr],
        delivery_group_size: usize,
        msg: Bytes,
    ) -> Result<(), SendError> {
        trace!(
            "Sending message ({} bytes) to {} of {:?}",
            msg.len(),
            delivery_group_size,
            recipients
        );

        if recipients.len() < delivery_group_size {
            warn!(
                "Less than delivery_group_size valid recipients - delivery_group_size: {}, recipients: {:?}",
                delivery_group_size,
                recipients,
            );
        }

        // Use `FuturesUnordered` to execute all the send tasks concurrently, but still on the same
        // thread. Keep track of the sending progress using the `SendState` helper.
        let mut state = SendState::new(recipients, delivery_group_size);
        let mut tasks = FuturesUnordered::new();

        loop {
            // Start a batch of sends.
            while let Some(addr) = state.next() {
                let msg = msg.clone();
                let task = async move {
                    let result = self.send_once(&addr, msg).await;
                    (addr, result)
                };
                tasks.push(task);
            }

            // Await until one of the started sends completes.
            if let Some((addr, result)) = tasks.next().await {
                // Notify `SendState` about the result of the send and potentially start the next
                // send, appending to the ones still in progress (if any).
                match result {
                    Ok(_) => state.success(&addr),
                    Err(err) => {
                        trace!(
                            "Sending message ({} bytes) to {} failed: {}",
                            msg.len(),
                            addr,
                            err
                        );
                        state.failure(&addr);
                    }
                }
            } else {
                // No sends in progress, we are done.
                break;
            }
        }

        let failed_recipients = state.finish();

        trace!(
            "Sending message ({} bytes) finished to {}/{} recipients (failed: {:?})",
            msg.len(),
            delivery_group_size - failed_recipients.len(),
            delivery_group_size,
            failed_recipients
        );

        if failed_recipients.is_empty() {
            Ok(())
        } else {
            Err(SendError { failed_recipients })
        }
    }

    // Low-level send
    async fn send_once(&self, recipient: &SocketAddr, msg: Bytes) -> Result<(), qp2p::Error> {
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

        let result = conn.send_uni(msg).await;

        // In case of error, remove the cached connection so it can be re-established on the next
        // attempt.
        if result.is_err() {
            let _ = self.node_conns.lock().await.remove(recipient);
        }

        result
    }
}

#[derive(Debug, Error)]
#[error(display = "Send failed to: {:?}", failed_recipients)]
pub struct SendError {
    // Recipients that failed all the send attempts.
    pub failed_recipients: Vec<SocketAddr>,
}

impl From<SendError> for Error {
    fn from(_: SendError) -> Self {
        Error::FailedSend
    }
}

// Helper to track the sending of a single message to potentially multiple recipients.
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

    // Returns the next recipient to send to.
    fn next(&mut self) -> Option<SocketAddr> {
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

        Some(recipient.addr)
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

    // Consumes the state and returns the list of recipients that failed all attempts (if any).
    fn finish(self) -> Vec<SocketAddr> {
        self.recipients
            .into_iter()
            .filter(|recipient| !recipient.sending && recipient.attempt >= RESEND_MAX_ATTEMPTS)
            .map(|recipient| recipient.addr)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use futures::future;
    use std::{
        net::{IpAddr, Ipv4Addr},
        slice,
        time::Duration,
    };
    use tokio::{net::UdpSocket, sync::mpsc, time};

    const TIMEOUT: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn successful_send() -> Result<()> {
        let comm = Comm::new(transport_config())?;

        let mut peer0 = Peer::new()?;
        let mut peer1 = Peer::new()?;

        let message = Bytes::from_static(b"hello world");
        comm.send_message_to_targets(&[peer0.addr, peer1.addr], 2, message.clone())
            .await?;

        assert_eq!(peer0.rx.recv().await, Some(message.clone()));
        assert_eq!(peer1.rx.recv().await, Some(message));

        Ok(())
    }

    #[tokio::test]
    async fn successful_send_to_subset() -> Result<()> {
        let comm = Comm::new(transport_config())?;

        let mut peer0 = Peer::new()?;
        let mut peer1 = Peer::new()?;

        let message = Bytes::from_static(b"hello world");
        comm.send_message_to_targets(&[peer0.addr, peer1.addr], 1, message.clone())
            .await?;

        assert_eq!(peer0.rx.recv().await, Some(message));

        assert!(time::timeout(TIMEOUT, peer1.rx.recv())
            .await
            .unwrap_or_default()
            .is_none());

        Ok(())
    }

    #[tokio::test]
    async fn failed_send() -> Result<()> {
        let comm = Comm::new(transport_config())?;
        let invalid_addr = get_invalid_addr().await?;

        let message = Bytes::from_static(b"hello world");
        match comm
            .send_message_to_targets(&[invalid_addr], 1, message.clone())
            .await
        {
            Err(error) => assert_eq!(error.failed_recipients, [invalid_addr]),
            Ok(_) => panic!("unexpected success"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn successful_send_after_failed_attempts() -> Result<()> {
        let comm = Comm::new(transport_config())?;
        let mut peer = Peer::new()?;
        let invalid_addr = get_invalid_addr().await?;

        let message = Bytes::from_static(b"hello world");
        comm.send_message_to_targets(&[invalid_addr, peer.addr], 1, message.clone())
            .await?;

        assert_eq!(peer.rx.recv().await, Some(message));

        Ok(())
    }

    #[tokio::test]
    async fn partially_successful_send() -> Result<()> {
        let comm = Comm::new(transport_config())?;
        let mut peer = Peer::new()?;
        let invalid_addr = get_invalid_addr().await?;

        let message = Bytes::from_static(b"hello world");

        match comm
            .send_message_to_targets(&[invalid_addr, peer.addr], 2, message.clone())
            .await
        {
            Ok(_) => panic!("unexpected success"),
            Err(error) => assert_eq!(error.failed_recipients, [invalid_addr]),
        }

        assert_eq!(peer.rx.recv().await, Some(message));

        Ok(())
    }

    #[tokio::test]
    async fn send_after_reconnect() -> Result<()> {
        let send_comm = Comm::new(transport_config())?;

        let recv_transport = QuicP2p::with_config(Some(transport_config()), &[], false)?;
        let recv_endpoint = recv_transport.new_endpoint()?;
        let recv_addr = recv_endpoint.local_addr()?;
        let mut recv_incoming_connections = recv_endpoint.listen()?;

        // Send the first message.
        let msg0 = Bytes::from_static(b"zero");
        send_comm
            .send_message_to_targets(slice::from_ref(&recv_addr), 1, msg0.clone())
            .await?;

        let mut msg0_received = false;

        // Receive one message and drop the incoming stream.
        {
            if let Some(mut incoming_msgs) =
                time::timeout(TIMEOUT, recv_incoming_connections.next()).await?
            {
                if let Some(msg) = time::timeout(TIMEOUT, incoming_msgs.next()).await? {
                    assert_eq!(msg.get_message_data(), msg0);
                    msg0_received = true;
                }
            }

            assert!(msg0_received);
        }

        // Send the second message.
        let msg1 = Bytes::from_static(b"one");
        send_comm
            .send_message_to_targets(slice::from_ref(&recv_addr), 1, msg1.clone())
            .await?;

        let mut msg1_received = false;

        // Expect to receive the second message on a re-established connection.
        if let Some(mut incoming_msgs) =
            time::timeout(TIMEOUT, recv_incoming_connections.next()).await?
        {
            if let Some(msg) = time::timeout(TIMEOUT, incoming_msgs.next()).await? {
                assert_eq!(msg.get_message_data(), msg1);
                msg1_received = true;
            }
        }

        assert!(msg1_received);

        Ok(())
    }

    fn transport_config() -> qp2p::Config {
        qp2p::Config {
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            idle_timeout_msec: Some(1),
            ..Default::default()
        }
    }

    struct Peer {
        addr: SocketAddr,
        rx: mpsc::Receiver<Bytes>,
    }

    impl Peer {
        fn new() -> Result<Self> {
            let transport = QuicP2p::with_config(Some(transport_config()), &[], false)?;

            let endpoint = transport.new_endpoint()?;
            let addr = endpoint.local_addr()?;
            let mut incoming_connections = endpoint.listen()?;

            let (tx, rx) = mpsc::channel(1);

            let _ = tokio::spawn(async move {
                while let Some(mut connection) = incoming_connections.next().await {
                    let mut tx = tx.clone();
                    let _ = tokio::spawn(async move {
                        while let Some(message) = connection.next().await {
                            let _ = tx.send(message.get_message_data()).await;
                        }
                    });
                }
            });

            Ok(Self { addr, rx })
        }
    }

    async fn get_invalid_addr() -> Result<SocketAddr> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = socket.local_addr()?;

        // Keep the socket alive to keep the address bound, but don't read/write to it so any
        // attempt to connect to it will fail.
        let _ = tokio::spawn(async move {
            future::pending::<()>().await;
            let _ = socket;
        });

        Ok(addr)
    }
}
