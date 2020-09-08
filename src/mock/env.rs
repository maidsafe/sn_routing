// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    network_params::NetworkParams,
    qp2p::Network,
    rng::{self, MainRng, Seed, SeedPrinter},
};
use rand::SeedableRng;
use std::{
    cell::RefCell,
    io::Write,
    ops::{Deref, DerefMut},
    sync::Once,
};

static LOG_INIT: Once = Once::new();

/// Test environment. Should be created once at the beginning of each test.
pub struct Environment {
    rng: RefCell<MainRng>,
    network: Network,
    network_params: NetworkParams,
    seed_printer: Option<SeedPrinter>,
}

impl Environment {
    /// Construct new mock network.
    pub fn new(network_params: NetworkParams) -> Self {
        LOG_INIT.call_once(|| {
            env_logger::builder()
                // the test framework will capture the log output and show it only on failure.
                // Run the tests with --nocapture to override.
                .is_test(true)
                .format(|buf, record| {
                    writeln!(
                        buf,
                        "{:.1} {} ({}:{})",
                        record.level(),
                        record.args(),
                        record.file().unwrap_or("<unknown>"),
                        record.line().unwrap_or(0)
                    )
                })
                .init()
        });

        let seed = Seed::default();
        let network = Network::new();

        Self {
            rng: RefCell::new(MainRng::from_seed(seed)),
            network,
            network_params,
            seed_printer: Some(SeedPrinter::on_failure(seed)),
        }
    }

    /// Get the network params.
    pub fn network_params(&self) -> NetworkParams {
        self.network_params
    }

    /// Get the number of elders
    pub fn elder_size(&self) -> usize {
        self.network_params.elder_size
    }

    /// Get the recommended section size
    pub fn recommended_section_size(&self) -> usize {
        self.network_params.recommended_section_size
    }

    /// Poll the mock network.
    pub fn poll(&self) {
        self.network.poll(&mut *self.rng.borrow_mut())
    }

    /// Construct a new random number generator using a seed generated from random data provided by `self`.
    pub fn new_rng(&self) -> MainRng {
        rng::new_from(&mut *self.rng.borrow_mut())
    }

    /// Call this in tests annotated with `#[should_panic]` to suppress printing the seed. Will
    /// instead print the seed if the panic does *not* happen.
    pub fn expect_panic(&mut self) {
        if let Some(seed) = self.seed_printer.as_ref().map(|printer| *printer.seed()) {
            self.seed_printer = Some(SeedPrinter::on_success(seed));
        }
    }
}

impl Deref for Environment {
    type Target = Network;

    fn deref(&self) -> &Self::Target {
        &self.network
    }
}

impl DerefMut for Environment {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.network
    }
}
