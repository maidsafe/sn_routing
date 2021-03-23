// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::error::{Error, Result};
use crate::XorName;
use bytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use hex_fmt::HexFmt;
use qp2p::{Endpoint, QuicP2p};
use sn_messaging::MessageType;
use std::{
    fmt::{self, Debug, Formatter},
    net::SocketAddr,
    sync::RwLock,
};
use thiserror::Error;
use tokio::{sync::mpsc, task};

// Communication component of the node to interact with other nodes.
pub(crate) struct Comm {
    _quic_p2p: QuicP2p,
    endpoint: Endpoint,
    // Sender for connection events. Kept here so we can clone it and pass it to the incoming
    // messages handler every time we establish new connection. It's kept in an `Option` so we can
    // take it out and drop it on `terminate` which together with all the incoming message handlers
    // terminating closes the corresponding receiver.
    event_tx: RwLock<Option<mpsc::Sender<ConnectionEvent>>>,
}

impl Comm {
    pub async fn new(
        transport_config: qp2p::Config,
        event_tx: mpsc::Sender<ConnectionEvent>,
    ) -> Result<Self> {
        let quic_p2p = QuicP2p::with_config(Some(transport_config), Default::default(), true)?;

        // Don't bootstrap, just create an endpoint to listen to
        // the incoming messages from other nodes.
        // This also returns the a channel where we can listen for
        // disconnection events.
        let (endpoint, _incoming_connections, incoming_messages, disconnections) =
            quic_p2p.new_endpoint().await?;

        let _ = task::spawn(handle_incoming_messages(
            incoming_messages,
            event_tx.clone(),
        ));

        let _ = task::spawn(handle_disconnection_events(
            disconnections,
            event_tx.clone(),
        ));

        Ok(Self {
            _quic_p2p: quic_p2p,
            endpoint,
            event_tx: RwLock::new(Some(event_tx)),
        })
    }

    pub async fn bootstrap(
        transport_config: qp2p::Config,
        event_tx: mpsc::Sender<ConnectionEvent>,
    ) -> Result<(Self, SocketAddr)> {
        let quic_p2p = QuicP2p::with_config(Some(transport_config), Default::default(), true)?;

        // Bootstrap to the network returning the connection to a node.
        // We can use the returned channels to listen for incoming messages and disconnection events
        let (endpoint, _incoming_connections, incoming_messages, disconnections, bootstrap_addr) =
            quic_p2p.bootstrap().await?;

        let _ = task::spawn(handle_incoming_messages(
            incoming_messages,
            event_tx.clone(),
        ));

        let _ = task::spawn(handle_disconnection_events(
            disconnections,
            event_tx.clone(),
        ));

        Ok((
            Self {
                _quic_p2p: quic_p2p,
                endpoint,
                event_tx: RwLock::new(Some(event_tx)),
            },
            bootstrap_addr,
        ))
    }

    // Close all existing connections and stop accepting new ones.
    pub fn terminate(&self) {
        self.endpoint.close();
        let _ = self
            .event_tx
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .take();
    }

    pub fn our_connection_info(&self) -> SocketAddr {
        self.endpoint.socket_addr()
    }

    /// Sends a message on an existing connection. If no such connection exists, returns an error.
    pub async fn send_on_existing_connection(
        &self,
        recipient: (SocketAddr, XorName),
        mut msg: MessageType,
    ) -> Result<(), Error> {
        msg.update_header(None, Some(recipient.1));
        let bytes = msg.serialize()?;
        self.endpoint
            .send_message(bytes, &recipient.0)
            .await
            .map_err(|e| Error::Network(e))
    }

    /// Sends a message to multiple recipients. Attempts to send to `delivery_group_size`
    /// recipients out of the `recipients` list. If a send fails, attempts to send to the next peer
    /// until `delivery_goup_size` successful sends complete or there are no more recipients to
    /// try.
    ///
    /// Returns `Ok` if all of `delivery_group_size` sends succeeded and `Err` if less that
    /// `delivery_group_size` succeeded. Also returns all the failed recipients which can be used
    /// by the caller to identify lost peers.
    pub async fn send(
        &self,
        recipients: &[(SocketAddr, XorName)],
        delivery_group_size: usize,
        msg: MessageType,
    ) -> (Result<(), SendError>, Vec<SocketAddr>) {
        if recipients.len() < delivery_group_size {
            warn!(
                "Less than delivery_group_size valid recipients - delivery_group_size: {}, recipients: {:?}",
                delivery_group_size,
                recipients,
            );
        }

        let delivery_group_size = delivery_group_size.min(recipients.len());

        // Run all the sends concurrently (using `FuturesUnordered`). If any of them fails, pick
        // the next recipient and try to send to them. Proceed until the needed number of sends
        // succeeds or if there are no more recipients to pick.
        let send = |recipient: (SocketAddr, XorName), mut msg: MessageType| async move {
            msg.update_header(None, Some(recipient.1));
            match msg.serialize() {
                Ok(bytes) => {
                    trace!(
                        "Sending message ({} bytes) to {} of {:?}",
                        bytes.len(),
                        delivery_group_size,
                        recipient.0
                    );
                    (
                        self.send_to(&recipient.0, bytes)
                            .await
                            .map_err(|e| Error::Network(e)),
                        recipient.0,
                    )
                }
                Err(e) => (Err(Error::Messaging(e)), recipient.0),
            }
        };
        let mut tasks: FuturesUnordered<_> = recipients[0..delivery_group_size]
            .iter()
            .map(|(recipient, name)| send((recipient.clone(), name.clone()), msg.clone()))
            .collect();

        let mut next = delivery_group_size;
        let mut successes = 0;
        let mut failed_recipients = vec![];

        while let Some((result, addr)) = tasks.next().await {
            match result {
                Ok(()) => successes += 1,
                Err(Error::Network(qp2p::Error::Connection(
                    qp2p::ConnectionError::LocallyClosed,
                ))) => {
                    // The connection was closed by us which means we are terminating so let's cut
                    // this short.
                    return (Err(SendError), vec![]);
                }
                Err(_) => {
                    failed_recipients.push(addr.clone());

                    if next < recipients.len() {
                        tasks.push(send(recipients[next], msg.clone()));
                        next += 1;
                    }
                }
            }
        }

        trace!(
            "Sending message ({:?} bytes) finished to {}/{} recipients (failed: {:?})",
            msg,
            successes,
            delivery_group_size,
            failed_recipients
        );

        let result = if successes == delivery_group_size {
            Ok(())
        } else {
            Err(SendError)
        };

        (result, failed_recipients)
    }

    // Low-level send
    async fn send_to(&self, recipient: &SocketAddr, msg: Bytes) -> Result<(), qp2p::Error> {
        // This will attempt to use a cached connection
        if self
            .endpoint
            .send_message(msg.clone(), recipient)
            .await
            .is_ok()
        {
            return Ok(());
        }

        // If the sending of a message failed the connection would no longer
        // exist in the pool. So we connect again and then send the message.
        self.endpoint.connect_to(recipient).await?;
        self.endpoint.send_message(msg, recipient).await
    }
}

impl Drop for Comm {
    fn drop(&mut self) {
        self.endpoint.close()
    }
}

#[derive(Debug, Error)]
#[error("Send failed")]
pub struct SendError;

impl From<SendError> for Error {
    fn from(_: SendError) -> Self {
        Error::FailedSend
    }
}

pub(crate) enum ConnectionEvent {
    Received((SocketAddr, Bytes)),
    Disconnected(SocketAddr),
}

impl Debug for ConnectionEvent {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Received((src, msg)) => write!(f, "Received(src: {}, msg: {})", src, HexFmt(msg)),
            Self::Disconnected(addr) => write!(f, "Disconnected({})", addr),
        }
    }
}

async fn handle_disconnection_events(
    mut disconnections: qp2p::DisconnectionEvents,
    event_tx: mpsc::Sender<ConnectionEvent>,
) {
    while let Some(peer_addr) = disconnections.next().await {
        let _ = event_tx
            .send(ConnectionEvent::Disconnected(peer_addr))
            .await;
    }
}

async fn handle_incoming_messages(
    mut incoming_msgs: qp2p::IncomingMessages,
    event_tx: mpsc::Sender<ConnectionEvent>,
) {
    while let Some((src, msg)) = incoming_msgs.next().await {
        let _ = event_tx.send(ConnectionEvent::Received((src, msg))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use assert_matches::assert_matches;
    use futures::future;
    use qp2p::Config;
    use sn_messaging::{HeaderInfo, WireMsg};
    use std::{net::Ipv4Addr, slice, time::Duration};
    use tokio::{net::UdpSocket, sync::mpsc, time};

    #[allow(unused)]
    const TIMEOUT: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn successful_send() -> Result<()> {
        let (tx, _rx) = mpsc::channel(1);
        let comm = Comm::new(transport_config(), tx).await?;

        let mut peer0 = Peer::new().await?;
        let mut peer1 = Peer::new().await?;

        let mut original_message = new_ping_message();

        comm.send(
            &[(peer0.addr, peer0._name), (peer1.addr, peer1._name)],
            2,
            original_message.clone(),
        )
        .await
        .0?;

        if let Some(bytes) = peer0.rx.recv().await {
            original_message.update_header(None, Some(peer0._name));
            assert_eq!(WireMsg::deserialize(bytes)?, original_message.clone());
        }

        if let Some(bytes) = peer1.rx.recv().await {
            original_message.update_header(None, Some(peer1._name));
            assert_eq!(WireMsg::deserialize(bytes)?, original_message);
        }

        Ok(())
    }

    #[tokio::test]
    async fn successful_send_to_subset() -> Result<()> {
        let (tx, _rx) = mpsc::channel(1);
        let comm = Comm::new(transport_config(), tx).await?;

        let mut peer0 = Peer::new().await?;
        let mut peer1 = Peer::new().await?;

        let mut original_message = new_ping_message();
        comm.send(
            &[(peer0.addr, peer0._name), (peer1.addr, peer1._name)],
            1,
            original_message.clone(),
        )
        .await
        .0?;

        if let Some(bytes) = peer0.rx.recv().await {
            original_message.update_header(None, Some(peer0._name));
            assert_eq!(WireMsg::deserialize(bytes)?, original_message);
        }

        assert!(time::timeout(TIMEOUT, peer1.rx.recv())
            .await
            .unwrap_or_default()
            .is_none());

        Ok(())
    }

    #[tokio::test]
    async fn failed_send() -> Result<()> {
        let (tx, _rx) = mpsc::channel(1);
        let comm = Comm::new(
            Config {
                // This makes this test faster.
                idle_timeout_msec: Some(1),
                ..transport_config()
            },
            tx,
        )
        .await?;
        let invalid_addr = get_invalid_addr().await?;

        let (result, failed_recipients) = comm
            .send(&[(invalid_addr, XorName::random())], 1, new_ping_message())
            .await;
        assert!(result.is_err());
        assert_eq!(failed_recipients, [invalid_addr]);

        Ok(())
    }

    #[tokio::test]
    async fn successful_send_after_failed_attempts() -> Result<()> {
        let (tx, _rx) = mpsc::channel(1);
        let comm = Comm::new(
            Config {
                idle_timeout_msec: Some(1),
                ..transport_config()
            },
            tx,
        )
        .await?;
        let mut peer = Peer::new().await?;
        let invalid_addr = get_invalid_addr().await?;

        let mut message = new_ping_message();
        comm.send(
            &[(invalid_addr, XorName::random()), (peer.addr, peer._name)],
            1,
            message.clone(),
        )
        .await
        .0?;

        if let Some(bytes) = peer.rx.recv().await {
            message.update_header(None, Some(peer._name));
            assert_eq!(WireMsg::deserialize(bytes)?, message);
        }
        Ok(())
    }

    #[tokio::test]
    async fn partially_successful_send() -> Result<()> {
        let (tx, _rx) = mpsc::channel(1);
        let comm = Comm::new(
            Config {
                idle_timeout_msec: Some(1),
                ..transport_config()
            },
            tx,
        )
        .await?;
        let mut peer = Peer::new().await?;
        let invalid_addr = get_invalid_addr().await?;

        let mut message = new_ping_message();
        let (result, failed_recipients) = comm
            .send(
                &[(invalid_addr, XorName::random()), (peer.addr, peer._name)],
                2,
                message.clone(),
            )
            .await;

        assert!(result.is_err());
        assert_eq!(failed_recipients, [invalid_addr]);
        if let Some(bytes) = peer.rx.recv().await {
            message.update_header(None, Some(peer._name));
            assert_eq!(WireMsg::deserialize(bytes)?, message);
        }
        Ok(())
    }

    #[tokio::test]
    async fn send_after_reconnect() -> Result<()> {
        let (tx, _rx) = mpsc::channel(1);
        let send_comm = Comm::new(transport_config(), tx).await?;

        let recv_transport = QuicP2p::with_config(Some(transport_config()), &[], false)?;
        let (recv_endpoint, _, mut incoming_msgs, _) = recv_transport.new_endpoint().await?;
        let recv_addr = recv_endpoint.socket_addr();
        let name = XorName::random();

        // Send the first message.
        let key0 = bls::SecretKey::random().public_key();
        let msg0 = MessageType::Ping(HeaderInfo {
            dest: name,
            dest_section_pk: key0,
        });
        send_comm
            .send(slice::from_ref(&(recv_addr, name)), 1, msg0.clone())
            .await
            .0?;

        let mut msg0_received = false;

        // Receive one message and disconnect from the peer
        {
            if let Some((src, msg)) = time::timeout(TIMEOUT, incoming_msgs.next()).await? {
                assert_eq!(WireMsg::deserialize(msg)?, msg0);
                msg0_received = true;
                recv_endpoint.disconnect_from(&src)?;
            }
            assert!(msg0_received);
        }

        // Send the second message.
        // Send the first message.
        let key1 = bls::SecretKey::random().public_key();
        let msg1 = MessageType::Ping(HeaderInfo {
            dest: name,
            dest_section_pk: key1,
        });
        send_comm
            .send(slice::from_ref(&(recv_addr, name)), 1, msg1.clone())
            .await
            .0?;

        let mut msg1_received = false;

        if let Some((_src, msg)) = time::timeout(TIMEOUT, incoming_msgs.next()).await? {
            assert_eq!(WireMsg::deserialize(msg)?, msg1);
            msg1_received = true;
        }

        assert!(msg1_received);

        Ok(())
    }

    #[tokio::test]
    async fn incoming_connection_lost() -> Result<()> {
        let (tx, mut rx0) = mpsc::channel(1);
        let comm0 = Comm::new(transport_config(), tx).await?;
        let addr0 = comm0.our_connection_info();

        let (tx, _rx) = mpsc::channel(1);
        let comm1 = Comm::new(transport_config(), tx).await?;
        let addr1 = comm1.our_connection_info();

        // Send a message to establish the connection
        comm1
            .send(
                slice::from_ref(&(addr0, XorName::random())),
                1,
                new_ping_message(),
            )
            .await
            .0?;
        assert_matches!(rx0.recv().await, Some(ConnectionEvent::Received(_)));
        // Drop `comm1` to cause connection lost.
        drop(comm1);

        assert_matches!(
            time::timeout(TIMEOUT, rx0.recv()).await?,
            Some(ConnectionEvent::Disconnected(addr)) => assert_eq!(addr, addr1)
        );

        Ok(())
    }

    fn transport_config() -> Config {
        Config {
            local_ip: Some(Ipv4Addr::LOCALHOST.into()),
            ..Default::default()
        }
    }

    fn new_ping_message() -> MessageType {
        MessageType::Ping(HeaderInfo {
            dest: XorName::random(),
            dest_section_pk: bls::SecretKey::random().public_key(),
        })
    }

    struct Peer {
        addr: SocketAddr,
        _incoming_connections: qp2p::IncomingConnections,
        _disconnections: qp2p::DisconnectionEvents,
        _name: XorName,
        rx: mpsc::Receiver<Bytes>,
    }

    impl Peer {
        async fn new() -> Result<Self> {
            let transport = QuicP2p::with_config(Some(transport_config()), &[], false)?;

            let (endpoint, incoming_connections, mut incoming_messages, disconnections) =
                transport.new_endpoint().await?;
            let addr = endpoint.socket_addr();

            let (tx, rx) = mpsc::channel(1);

            let _ = tokio::spawn(async move {
                while let Some((_src, msg)) = incoming_messages.next().await {
                    let _ = tx.send(msg).await;
                }
            });

            Ok(Self {
                addr,
                rx,
                _incoming_connections: incoming_connections,
                _disconnections: disconnections,
                _name: XorName::random(),
            })
        }
    }

    #[allow(unused)]
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
