// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::quic_p2p;
#[cfg(feature = "mock")]
use crate::mock::parsec;
use crate::{chain::NetworkParams, unwrap};
use maidsafe_utilities::log;
use std::{
    env,
    ops::{Deref, DerefMut},
    sync::Once,
};

static LOG_INIT: Once = Once::new();

/// Test environment. Should be created once at the beginning of each test.
#[derive(Clone)]
pub struct Network {
    network: quic_p2p::Network,
    network_cfg: NetworkParams,
}

impl Network {
    /// Construct new mock network.
    pub fn new(network_cfg: NetworkParams) -> Self {
        LOG_INIT.call_once(|| {
            if env::var("RUST_LOG")
                .map(|value| !value.is_empty())
                .unwrap_or(false)
            {
                unwrap!(log::init(true));
            }
        });

        #[cfg(feature = "mock")]
        parsec::init_mock();

        Self {
            network: quic_p2p::Network::new(),
            network_cfg,
        }
    }

    /// Get the chain network config.
    pub fn network_cfg(&self) -> NetworkParams {
        self.network_cfg
    }

    /// Get the number of elders
    pub fn elder_size(&self) -> usize {
        self.network_cfg.elder_size
    }

    /// Get the safe section size
    pub fn safe_section_size(&self) -> usize {
        self.network_cfg.safe_section_size
    }
}

impl Deref for Network {
    type Target = self::quic_p2p::Network;

    fn deref(&self) -> &Self::Target {
        &self.network
    }
}

impl DerefMut for Network {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.network
    }
}
