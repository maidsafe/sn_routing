// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod command;
pub mod event_stream;
mod executor;
mod stage;

pub use self::event_stream::EventStream;
use self::{
    command::{Command, Context},
    executor::Executor,
    stage::Stage,
};
use crate::{
    crypto::{name, Keypair, PublicKey},
    error::{Error, Result},
    location::{DstLocation, SrcLocation},
    network_params::NetworkParams,
    peer::Peer,
    rng::MainRng,
    section::{EldersInfo, SectionProofChain},
    TransportConfig,
};
use bytes::Bytes;
use itertools::Itertools;
use std::{net::SocketAddr, sync::Arc};
use xor_name::{Prefix, XorName};

/// Node configuration.
pub struct NodeConfig {
    /// If true, configures the node to start a new network instead of joining an existing one.
    pub first: bool,
    /// The `Keypair` of the node or `None` for randomly generated one.
    pub keypair: Option<Keypair>,
    /// Configuration for the underlying network transport.
    pub transport_config: TransportConfig,
    /// Global network parameters. Must be identical for all nodes in the network.
    pub network_params: NetworkParams,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            first: false,
            keypair: None,
            transport_config: TransportConfig::default(),
            network_params: NetworkParams::default(),
        }
    }
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full
/// sn_routing node.
///
/// A node is a part of the network that can route messages and be a member of a section or group
/// location. Its methods can be used to send requests and responses as either an individual
/// `Node` or as a part of a section or group location. Their `src` argument indicates that
/// role, and can be any [`SrcLocation`](enum.SrcLocation.html).
pub struct Node {
    stage: Arc<Stage>,
    _executor: Executor,
}

impl Node {
    ////////////////////////////////////////////////////////////////////////////
    // Public API
    ////////////////////////////////////////////////////////////////////////////

    /// Create new node using the given config.
    pub async fn new(config: NodeConfig) -> Result<(Self, EventStream)> {
        let mut cx = Context::new();
        let mut rng = MainRng::default();
        let keypair = config
            .keypair
            .unwrap_or_else(|| Keypair::generate(&mut rng));
        let node_name = name(&keypair.public);

        let (stage, incoming_conns, events_rx) = if config.first {
            info!("{} Starting a new network as the seed node.", node_name);
            Stage::first_node(config.transport_config, keypair, config.network_params).await?
        } else {
            info!("{} Bootstrapping a new node.", node_name);
            Stage::bootstrap(
                &mut cx,
                config.transport_config,
                keypair,
                config.network_params,
            )
            .await?
        };

        let stage = Arc::new(stage);
        let executor = Executor::new(stage.clone(), incoming_conns);
        let event_stream = EventStream::new(events_rx);

        // Process the initial commands.
        for command in cx.into_commands() {
            let _ = tokio::spawn(stage.clone().handle_command(command));
        }

        let node = Self {
            stage,
            _executor: executor,
        };

        Ok((node, event_stream))
    }

    /// Returns the `PublicKey` of this node.
    pub async fn public_key(&self) -> PublicKey {
        self.stage.public_key().await
    }

    /// The name of this node.
    pub async fn name(&self) -> XorName {
        self.stage.name().await
    }

    /// Returns connection info of this node.
    pub fn our_connection_info(&self) -> Result<SocketAddr> {
        self.stage.our_connection_info()
    }

    /// Our `Prefix` once we are a part of the section.
    pub async fn our_prefix(&self) -> Option<Prefix> {
        self.stage.our_prefix().await
    }

    /// Finds out if the given XorName matches our prefix. Returns error
    /// if we don't have a prefix because we haven't joined any section yet.
    pub async fn matches_our_prefix(&self, name: &XorName) -> Result<bool> {
        if let Some(prefix) = self.our_prefix().await {
            Ok(prefix.matches(name))
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Returns whether the node is Elder.
    pub async fn is_elder(&self) -> bool {
        self.stage.is_elder().await
    }

    /// Returns the information of all the current section elders.
    pub async fn our_elders(&self) -> Vec<Peer> {
        self.stage.our_elders().await
    }

    /// Returns the elders of our section sorted by their distance to `name` (closest first).
    pub async fn our_elders_sorted_by_distance_to(&self, name: &XorName) -> Vec<Peer> {
        self.our_elders()
            .await
            .into_iter()
            .sorted_by(|lhs, rhs| name.cmp_distance(lhs.name(), rhs.name()))
            .collect()
    }

    /// Returns the information of all the current section adults.
    pub async fn our_adults(&self) -> Vec<Peer> {
        self.stage.our_adults().await
    }

    /// Returns the adults of our section sorted by their distance to `name` (closest first).
    /// If we are not elder or if there are no adults in the section, returns empty vec.
    pub async fn our_adults_sorted_by_distance_to(&self, name: &XorName) -> Vec<Peer> {
        self.our_adults()
            .await
            .into_iter()
            .sorted_by(|lhs, rhs| name.cmp_distance(lhs.name(), rhs.name()))
            .collect()
    }

    /// Returns the info about our section or `None` if we are not joined yet.
    pub async fn our_section(&self) -> Option<EldersInfo> {
        self.stage.our_section().await
    }

    /// Returns the info about our neighbour sections.
    pub async fn neighbour_sections(&self) -> Vec<EldersInfo> {
        self.stage.neighbour_sections().await
    }

    /// Send a message.
    pub async fn send_message(
        &self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<()> {
        let command = Command::SendUserMessage { src, dst, content };
        self.stage.clone().handle_command(command).await
    }

    /// Send a message to a client peer.
    pub async fn send_message_to_client(
        &self,
        recipient: SocketAddr,
        message: Bytes,
    ) -> Result<()> {
        let command = Command::SendMessage {
            recipients: vec![recipient],
            delivery_group_size: 1,
            message,
        };
        self.stage.clone().handle_command(command).await
    }

    /// Returns the current BLS public key set or `Error::InvalidState` if we are not joined
    /// yet.
    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.stage.public_key_set().await
    }

    /// Returns the current BLS secret key share or `Error::InvalidState` if we are not
    /// elder.
    pub async fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        self.stage.secret_key_share().await
    }

    /// Returns our section proof chain, or `None` if we are not joined yet.
    pub async fn our_history(&self) -> Option<SectionProofChain> {
        self.stage.our_history().await
    }

    /// Returns our index in the current BLS group or `Error::InvalidState` if section key was
    /// not generated yet.
    pub async fn our_index(&self) -> Result<usize> {
        self.stage.our_index().await
    }
}
