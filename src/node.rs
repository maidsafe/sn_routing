// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chain::NetworkParams, core::CoreConfig, event::Event, id::FullId, rng, NetworkConfig,
    NetworkEvent,
};
use crossbeam_channel as mpmc;
use rand::RngCore;

pub use crate::states::ApprovedPeer as Node;

/// A builder to configure and create a new `Node`.
#[derive(Default)]
pub struct Builder {
    first: bool,
    config: CoreConfig,
}

impl Builder {
    /// Creates a new builder to configure and create a `Node`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures the node to start a new network instead of joining an existing one.
    pub fn first(self, first: bool) -> Self {
        Self { first, ..self }
    }

    /// The node will use the given network config rather than default.
    pub fn network_config(mut self, config: NetworkConfig) -> Self {
        self.config.network_config = config;
        self
    }

    /// The node will use the given full id rather than default, randomly generated one.
    pub fn full_id(mut self, full_id: FullId) -> Self {
        self.config.full_id = Some(full_id);
        self
    }

    /// Override the default network params.
    pub fn network_params(mut self, network_params: NetworkParams) -> Self {
        self.config.network_params = network_params;
        self
    }

    /// Use the supplied random number generator. If this is not called, a default `OsRng` is used.
    pub fn rng<R: RngCore>(mut self, rng: &mut R) -> Self {
        self.config.rng = rng::new_from(rng);
        self
    }

    /// Creates new `Node`.
    pub fn create(self) -> (Node, mpmc::Receiver<Event>, mpmc::Receiver<NetworkEvent>) {
        Node::new(self.config, self.first)
    }
}
