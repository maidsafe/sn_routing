// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::{Error, Result},
    id::FullId,
    location::DstLocation,
    messages::{Message, Variant},
};
use bytes::Bytes;
use futures::lock::Mutex;
use hex_fmt::HexFmt;
use lru_time_cache::LruCache;
use qp2p::{Config, Connection, Endpoint, IncomingConnections, QuicP2p};
use std::{net::SocketAddr, sync::Arc};

// Number of Connections to maintain in the cache
const CONNECTIONS_CACHE_SIZE: usize = 1024;

// Communication component of the node to interact with other nodes.
#[derive(Clone)]
pub(crate) struct Comm {
    quic_p2p: Arc<QuicP2p>,
    endpoint: Arc<Endpoint>,
    node_conns: Arc<Mutex<LruCache<SocketAddr, Connection>>>,
}

impl Comm {
    pub async fn new(transport_config: Config) -> Result<Self> {
        let quic_p2p = Arc::new(QuicP2p::with_config(
            Some(transport_config),
            Default::default(),
            true,
        )?);

        // Don't bootstrap, just create an endpoint where to listen to
        // the incoming messages from other nodes.
        let endpoint = Arc::new(quic_p2p.new_endpoint()?);

        let node_conns = Arc::new(Mutex::new(LruCache::with_capacity(CONNECTIONS_CACHE_SIZE)));

        Ok(Self {
            quic_p2p,
            endpoint,
            node_conns,
        })
    }

    pub async fn from_bootstrapping(transport_config: Config) -> Result<(Self, SocketAddr)> {
        let mut quic_p2p = QuicP2p::with_config(Some(transport_config), Default::default(), true)?;

        // Bootstrap to the network returning the connection to a node.
        let (endpoint, connection) = quic_p2p.bootstrap().await?;

        let quic_p2p = Arc::new(quic_p2p);
        let endpoint = Arc::new(endpoint);

        let addr = connection.remote_address();

        let mut node_conns = LruCache::with_capacity(CONNECTIONS_CACHE_SIZE);
        let _ = node_conns.insert(addr, connection);

        Ok((
            Self {
                quic_p2p,
                endpoint,
                node_conns: Arc::new(Mutex::new(node_conns)),
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

    pub async fn send_message_to_targets(
        &self,
        conn_infos: &[SocketAddr],
        delivery_group_size: usize,
        msg: Bytes,
    ) -> Result<()> {
        if conn_infos.len() < delivery_group_size {
            warn!(
                "Less than delivery_group_size valid targets! delivery_group_size = {}; targets = {:?}; msg = {:10}",
                delivery_group_size,
                conn_infos,
                HexFmt(&msg)
            );
        }

        // TODO: retry upon failures. Timeout could perhaps still
        // be handlded by user...?
        trace!(
            "Sending message to {:?}",
            &conn_infos[..delivery_group_size.min(conn_infos.len())]
        );

        // initially only send to delivery_group_size targets
        for addr in conn_infos.iter().take(delivery_group_size) {
            // NetworkBytes is refcounted and cheap to clone.
            self.send_message_to_target(addr, msg.clone()).await?;
        }

        Ok(())
    }

    pub async fn send_message_to_target(&self, recipient: &SocketAddr, msg: Bytes) -> Result<()> {
        trace!("Sending message to target {:?}", recipient);
        // Cache the Connection to the node or obtain the already cached one
        let mut node_conns = self.node_conns.lock().await;
        let conn = node_conns
            .entry(*recipient)
            .or_insert(self.endpoint.connect_to(recipient).await?);
        conn.send_uni(msg).await.map_err(Error::Network)
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
