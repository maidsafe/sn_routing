// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "mock")]
use crate::mock::parsec;
use crate::{
    chain::NetworkParams,
    location::DstLocation,
    messages::SrcAuthority,
    quic_p2p::Network,
    rng::{self, MainRng, Seed, SeedPrinter},
    unwrap,
};
use maidsafe_utilities::log;
use rand::SeedableRng;
use std::{
    cell::{Cell, RefCell},
    env,
    ops::{Deref, DerefMut},
    rc::Rc,
    sync::Once,
};

static LOG_INIT: Once = Once::new();

/// Test environment. Should be created once at the beginning of each test.
pub struct Environment {
    rng: RefCell<MainRng>,
    network: Network,
    network_cfg: NetworkParams,
    seed_printer: Option<SeedPrinter>,
    message_sent: Rc<Cell<bool>>,
}

impl Environment {
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

        let seed = Seed::default();
        let network = Network::new();

        let message_sent = Rc::new(Cell::new(false));
        network.set_message_sent_hook({
            let message_sent = Rc::clone(&message_sent);
            move |bytes| {
                if !is_parsec_gossip_message(&bytes[..]) {
                    message_sent.set(true)
                }
            }
        });

        Self {
            rng: RefCell::new(MainRng::from_seed(seed)),
            network,
            network_cfg,
            seed_printer: Some(SeedPrinter::on_failure(seed)),
            message_sent,
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

    /// Poll the mock network.
    pub fn poll(&self) {
        self.network.poll(&mut *self.rng.borrow_mut());
    }

    /// Returns whether any non-gossip message has been sent since the creation of this struct or
    /// the last time this function was called. This can be used to decide whether to keep polling.
    /// Gossip messages are not considered because they are always sent.
    pub fn message_sent(&self) -> bool {
        self.message_sent.replace(false)
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

impl Clone for Environment {
    fn clone(&self) -> Self {
        Self {
            rng: RefCell::new(self.new_rng()),
            network: self.network.clone(),
            network_cfg: self.network_cfg,
            seed_printer: None,
            message_sent: Rc::clone(&self.message_sent),
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

#[derive(Deserialize)]
struct PartialMessage {
    _dst: DstLocation,
    _src: SrcAuthority,
    variant: u32,
}

const PARSEC_REQUEST_TAG: u32 = 11;
const PARSEC_RESPONSE_TAG: u32 = 12;

// Detect whether the given serialize message contains a parsec gossip.
fn is_parsec_gossip_message(bytes: &[u8]) -> bool {
    let tag = message_tag(bytes);
    tag == PARSEC_REQUEST_TAG || tag == PARSEC_RESPONSE_TAG
}

fn message_tag(bytes: &[u8]) -> u32 {
    let message: PartialMessage = unwrap!(bincode::deserialize(bytes));
    message.variant
}

#[cfg(all(test, feature = "mock"))]
mod test {
    use super::*;
    use crate::{
        id::FullId,
        messages::{Message, Variant},
        parsec::{Request, Response},
        rng,
    };
    use rand::Rng;

    #[test]
    fn parsec_gossip_message_tags() {
        let mut rng = rng::new();
        let full_id = FullId::gen(&mut rng);
        let dst = DstLocation::Node(rng.gen());

        let make_message_bytes = |variant| {
            let message = unwrap!(Message::single_src(&full_id, dst, variant));
            unwrap!(message.to_bytes())
        };

        let bytes = make_message_bytes(Variant::ParsecRequest(1, Request::new()));
        assert_eq!(message_tag(&bytes[..]), PARSEC_REQUEST_TAG);

        let bytes = make_message_bytes(Variant::ParsecResponse(1, Response::new()));
        assert_eq!(message_tag(&bytes[..]), PARSEC_RESPONSE_TAG);
    }
}
