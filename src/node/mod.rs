// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod event_stream;
mod stage;
#[cfg(all(test, feature = "mock"))]
mod tests;

#[cfg(feature = "mock")]
pub use self::stage::{BOOTSTRAP_TIMEOUT, JOIN_TIMEOUT};

pub use event_stream::EventStream;

use self::stage::Stage;
use crate::{
    error::{Error, Result},
    id::{FullId, P2pNode, PublicId},
    location::{DstLocation, SrcLocation},
    log_utils,
    network_params::NetworkParams,
    rng::MainRng,
    section::{EldersInfo, SectionProofChain},
    TransportConfig,
};
use bytes::Bytes;
use futures::lock::Mutex;
use itertools::Itertools;
use std::{net::SocketAddr, sync::Arc};
use xor_name::{Prefix, XorName};

#[cfg(all(test, feature = "mock"))]
use crate::section::SectionKeyShare;
#[cfg(feature = "mock")]
use std::collections::BTreeSet;

/// Node configuration.
pub struct NodeConfig {
    /// If true, configures the node to start a new network instead of joining an existing one.
    pub first: bool,
    /// The ID of the node or `None` for randomly generated one.
    pub full_id: Option<FullId>,
    /// Configuration for the underlying network transport.
    pub transport_config: TransportConfig,
    /// Global network parameters. Must be identical for all nodes in the network.
    pub network_params: NetworkParams,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            first: false,
            full_id: None,
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
#[derive(Clone)]
pub struct Node {
    stage: Arc<Mutex<Stage>>,
}

impl Node {
    ////////////////////////////////////////////////////////////////////////////
    // Public API
    ////////////////////////////////////////////////////////////////////////////

    /// Create new node using the given config.
    pub async fn new(config: NodeConfig) -> Result<(Self, EventStream)> {
        let mut rng = MainRng::default();
        let full_id = config.full_id.unwrap_or_else(|| FullId::gen(&mut rng));
        let node_name = *full_id.public_id().name();
        let transport_config = config.transport_config;
        let network_params = config.network_params;
        let is_genesis = config.first;

        let (stage, incoming_conns, timer_rx, events_rx) = if is_genesis {
            match Stage::first_node(transport_config, full_id, network_params).await {
                Ok(stage_and_conns_stream) => {
                    info!("{} Started a new network as a seed node.", node_name);
                    stage_and_conns_stream
                }
                Err(error) => {
                    error!("{} Failed to start the first node: {:?}", node_name, error);
                    return Err(error);
                }
            }
        } else {
            info!("{} Bootstrapping a new node.", node_name);
            Stage::bootstrap(transport_config, full_id, network_params).await?
        };

        let stage = Arc::new(Mutex::new(stage));

        let event_stream =
            EventStream::new(Arc::clone(&stage), incoming_conns, timer_rx, events_rx).await?;

        Ok((Self { stage }, event_stream))
    }

    /// Returns the `PublicId` of this node.
    pub async fn id(&self) -> PublicId {
        *self.stage.lock().await.full_id().public_id()
    }

    /// The name of this node.
    pub async fn name(&self) -> XorName {
        *self.id().await.name()
    }

    /// Returns connection info of this node.
    pub async fn our_connection_info(&self) -> Result<SocketAddr> {
        self.stage.lock().await.our_connection_info()
    }

    /// Our `Prefix` once we are a part of the section.
    pub async fn our_prefix(&self) -> Option<Prefix> {
        self.stage.lock().await.our_prefix().cloned()
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
        let stage = self.stage.lock().await;
        match stage.approved() {
            None => false,
            Some(state) => state
                .shared_state
                .sections
                .our()
                .elders
                .contains_key(stage.full_id().public_id().name()),
        }
    }

    /// Returns the information of all the current section elders.
    pub async fn our_elders(&self) -> Vec<P2pNode> {
        match self.stage.lock().await.approved() {
            Some(stage) => stage.shared_state.sections.our_elders().cloned().collect(),
            None => vec![],
        }
    }

    /// Returns the elders of our section sorted by their distance to `name` (closest first).
    pub async fn our_elders_sorted_by_distance_to(&self, name: &XorName) -> Vec<P2pNode> {
        match self.stage.lock().await.approved() {
            Some(stage) => stage
                .shared_state
                .sections
                .our_elders()
                .sorted_by(|lhs, rhs| name.cmp_distance(lhs.name(), rhs.name()))
                .cloned()
                .collect(),
            None => vec![],
        }
    }

    /// Returns the information of all the current section adults.
    pub async fn our_adults(&self) -> Vec<P2pNode> {
        match self.stage.lock().await.approved() {
            Some(stage) => stage.shared_state.our_adults().cloned().collect(),
            None => vec![],
        }
    }

    /// Returns the adults of our section sorted by their distance to `name` (closest first).
    /// If we are not elder or if there are no adults in the section, returns empty vec.
    pub async fn our_adults_sorted_by_distance_to(&self, name: &XorName) -> Vec<P2pNode> {
        match self.stage.lock().await.approved() {
            Some(stage) => stage
                .shared_state
                .our_adults()
                .sorted_by(|lhs, rhs| name.cmp_distance(lhs.name(), rhs.name()))
                .cloned()
                .collect(),
            None => vec![],
        }
    }

    /// Returns the info about our section or `None` if we are not joined yet.
    pub async fn our_section(&self) -> Option<EldersInfo> {
        match self.stage.lock().await.approved() {
            Some(stage) => Some(stage.shared_state.sections.our().clone()),
            None => None,
        }
    }

    /// Returns the info about our neighbour sections.
    pub async fn neighbour_sections(&self) -> Vec<EldersInfo> {
        match self.stage.lock().await.approved() {
            Some(stage) => stage.shared_state.sections.neighbours().cloned().collect(),
            None => vec![],
        }
    }

    /// Send a message.
    pub async fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<()> {
        if let DstLocation::Direct = dst {
            return Err(Error::BadLocation);
        }

        // Set log identifier
        let str = self.stage.lock().await.name_and_prefix();
        use std::fmt::Write;
        let _log_ident = log_utils::set_ident(|buffer| write!(buffer, "{}", str));

        self.stage
            .lock()
            .await
            .send_message(src, dst, content)
            .await
    }

    /// Send a message to a client peer.
    pub async fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        self.stage
            .lock()
            .await
            .send_message_to_target(&peer_addr, msg)
            .await
    }

    /// Returns the current BLS public key set or `Error::InvalidState` if we are not joined
    /// yet.
    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.stage
            .lock()
            .await
            .approved()
            .and_then(|stage| stage.section_key_share())
            .map(|share| share.public_key_set.clone())
            .ok_or(Error::InvalidState)
    }

    /// Returns the current BLS secret key share or `Error::InvalidState` if we are not
    /// elder.
    pub async fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        self.stage
            .lock()
            .await
            .approved()
            .and_then(|stage| stage.section_key_share())
            .map(|share| share.secret_key_share.clone())
            .ok_or(Error::InvalidState)
    }

    /// Returns our section proof chain, or `None` if we are not joined yet.
    pub async fn our_history(&self) -> Option<SectionProofChain> {
        self.stage
            .lock()
            .await
            .approved()
            .map(|stage| stage.shared_state.our_history.clone())
    }

    /// Returns our index in the current BLS group or `Error::InvalidState` if section key was
    /// not generated yet.
    pub async fn our_index(&self) -> Result<usize> {
        self.stage
            .lock()
            .await
            .approved()
            .and_then(|stage| stage.section_key_share())
            .map(|share| share.index)
            .ok_or(Error::InvalidState)
    }
}

#[cfg(feature = "mock")]
impl Node {
    /// Returns whether the node is approved member of a section.
    pub fn is_approved(&self) -> bool {
        self.stage
            .approved()
            .map(|stage| stage.is_ready(&self.core))
            .unwrap_or(false)
    }

    /// Checks whether the given location represents self.
    pub fn in_src_location(&self, src: &SrcLocation) -> bool {
        src.contains(self.core.name())
    }

    /// Returns the info about our neighbour sections.
    pub fn neighbour_sections(&self) -> impl Iterator<Item = &EldersInfo> {
        self.shared_state()
            .into_iter()
            .flat_map(|state| state.sections.neighbours())
    }

    /// Returns the info about our sections or `None` if we are not joined yet.
    pub fn our_section(&self) -> Option<&EldersInfo> {
        self.shared_state().map(|state| state.sections.our())
    }

    /// Returns the prefixes of all sections known to us
    pub fn prefixes(&self) -> BTreeSet<Prefix> {
        self.shared_state()
            .map(|state| state.sections.prefixes().copied().collect())
            .unwrap_or_default()
    }

    /// Returns the elders in our and neighbouring sections.
    pub fn known_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.shared_state()
            .into_iter()
            .flat_map(|state| state.sections.elders())
    }

    /// Returns whether the given peer is an elder known to us.
    pub fn is_peer_elder(&self, name: &XorName) -> bool {
        self.shared_state()
            .map(|state| state.is_peer_elder(name))
            .unwrap_or(false)
    }

    /// Returns whether the given peer is an elder of our section.
    pub fn is_peer_our_elder(&self, name: &XorName) -> bool {
        self.shared_state()
            .map(|state| state.is_peer_our_elder(name))
            .unwrap_or(false)
    }

    /// Returns the members in our section and elders we know.
    pub fn known_nodes(&self) -> impl Iterator<Item = &P2pNode> {
        self.shared_state()
            .into_iter()
            .flat_map(|state| state.known_nodes())
    }

    /// Returns whether the given `XorName` is a member of our section.
    pub fn is_peer_our_member(&self, name: &XorName) -> bool {
        self.shared_state()
            .map(|state| state.our_members.is_joined(name))
            .unwrap_or(false)
    }

    /// Returns their knowledge
    pub fn get_their_knowledge(&self, prefix: &Prefix) -> u64 {
        self.shared_state()
            .map(|state| state.sections.knowledge_by_section(prefix))
            .unwrap_or(0)
    }

    /// If our section is the closest one to `name`, returns all names in our section *including
    /// ours*, otherwise returns `None`.
    pub fn close_names(&self, name: &XorName) -> Option<Vec<XorName>> {
        let state = self.shared_state()?;
        if state.our_prefix().matches(name) {
            Some(
                state
                    .sections
                    .our_elders()
                    .map(|p2p_node| *p2p_node.name())
                    .collect(),
            )
        } else {
            None
        }
    }

    /// Returns the number of elders this node is using.
    pub fn elder_size(&self) -> usize {
        self.core.network_params().elder_size
    }

    /// Size at which our section splits. Since this is configurable, this method is used to
    /// obtain it.
    pub fn recommended_section_size(&self) -> usize {
        self.core.network_params().recommended_section_size
    }

    /// Returns the age of the node with `name` if this node knows it. Otherwise returns `None`.
    pub fn member_age(&self, name: &XorName) -> Option<u8> {
        self.stage
            .approved()
            .and_then(|stage| stage.shared_state.our_members.get(name))
            .map(|info| info.age)
    }

    /// Returns the latest BLS public key of our section or `None` if we are not joined yet.
    pub fn section_key(&self) -> Option<&bls::PublicKey> {
        self.shared_state.map(|state| state.our_history.last_key())
    }

    pub(crate) fn shared_state(&self) -> Option<&SharedState> {
        self.stage.approved().map(|stage| &stage.shared_state)
    }
}

#[cfg(all(test, feature = "mock"))]
impl Node {
    // Create new node which is already an approved member of a section.
    pub(crate) fn approved(
        config: NodeConfig,
        shared_state: SharedState,
        section_key_share: Option<SectionKeyShare>,
    ) -> (Self, Receiver<Event>, Receiver<TransportEvent>) {
        let (timer_tx, timer_rx) = crossbeam_channel::unbounded();
        let (transport_tx, transport_node_rx, transport_client_rx) = transport_channels();
        let (user_event_tx, user_event_rx) = crossbeam_channel::unbounded();

        let core = Core::new(config, timer_tx, transport_tx, user_event_tx);

        let stage = Approved::new(shared_state, section_key_share).unwrap();
        let stage = Stage::Approved(stage);

        let node = Self {
            stage,
            core,
            timer_rx,
            timer_rx_idx: 0,
            transport_rx: transport_node_rx,
            transport_rx_idx: 0,
        };

        (node, user_event_rx, transport_client_rx)
    }

    // Simulate DKG completion
    pub(crate) fn complete_dkg(
        &mut self,
        elders_info: &EldersInfo,
        public_key_set: bls::PublicKeySet,
        secret_key_share: Option<bls::SecretKeyShare>,
    ) -> Result<()> {
        if let Some(stage) = self.stage.approved_mut() {
            stage.complete_dkg(
                &mut self.core,
                elders_info,
                public_key_set,
                secret_key_share,
            )
        } else {
            Err(Error::InvalidState)
        }
    }
}
