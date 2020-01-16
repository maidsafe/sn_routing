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
    quic_p2p::Network,
    rng::{self, MainRng, Seed, SeedPrinter},
    unwrap,
};
use bytes::Bytes;
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
    message_sent: Rc<Cell<bool>>,
    seed_printer: Option<SeedPrinter>,
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
            move |content| {
                if !is_periodic_message(content) {
                    message_sent.set(true)
                }
            }
        });

        Self {
            rng: RefCell::new(MainRng::from_seed(seed)),
            network,
            network_cfg,
            message_sent,
            seed_printer: Some(SeedPrinter::on_failure(seed)),
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
        self.network.poll(&mut *self.rng.borrow_mut())
    }

    /// Construct a new random number generator using a seed generated from random data provided by `self`.
    pub fn new_rng(&self) -> MainRng {
        rng::new_from(&mut *self.rng.borrow_mut())
    }

    /// Return whether sent any message since previous query and reset the flag.
    pub fn reset_message_sent(&self) -> bool {
        self.message_sent.replace(false)
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
            message_sent: Rc::clone(&self.message_sent),
            seed_printer: None,
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

// Periodically sent messages start with these bytes when serialised.
const PERIODIC_MSG_TAGS: &[&[u8]] = &[
    // MemberKnowledge
    &[0, 0, 0, 0, 5, 0, 0, 0],
    // ParsecRequest
    &[0, 0, 0, 0, 6, 0, 0, 0],
    // ParsecResponse
    &[0, 0, 0, 0, 7, 0, 0, 0],
];

// Returns `true` if this message is sent periodically (on timer tick).
// Sending a periodic message doesn't set the `messages_sent` flag which is a hack/workaround to
// avoid infinite poll loop.
fn is_periodic_message(content: &Bytes) -> bool {
    content.len() >= 8 && PERIODIC_MSG_TAGS.contains(&&content[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        id::FullId,
        messages::{
            DirectMessage, HopMessage, MemberKnowledge, Message, MessageContent, RoutingMessage,
            SignedDirectMessage, SignedRoutingMessage,
        },
        parsec::{Request, Response},
        rng, unwrap, Authority,
    };
    use maidsafe_utilities::serialisation;
    use rand::Rng;
    use serde::Serialize;

    #[test]
    fn message_is_periodic() {
        let mut rng = rng::new();
        let full_id = FullId::gen(&mut rng);

        fn serialise<T: Serialize>(msg: &T) -> Vec<u8> {
            unwrap!(serialisation::serialise(&msg))
        }

        let make_message =
            |content| Message::Direct(unwrap!(SignedDirectMessage::new(content, &full_id)));

        // Real parsec doesn't provide constructors for requests and responses, but they have the same
        // representation as a `Vec`.
        #[cfg(not(feature = "mock"))]
        let (req, rsp): (Request, Response) = {
            let repr = Vec::<u64>::new();

            (
                unwrap!(serialisation::deserialise(&serialise(&repr))),
                unwrap!(serialisation::deserialise(&serialise(&repr))),
            )
        };

        #[cfg(feature = "mock")]
        let (req, rsp) = (Request::new(), Response::new());

        let msgs = [
            make_message(DirectMessage::MemberKnowledge(MemberKnowledge {
                elders_version: 23,
                parsec_version: 24,
            })),
            make_message(DirectMessage::ParsecRequest(42, req)),
            make_message(DirectMessage::ParsecResponse(1337, rsp)),
        ];
        for msg in &msgs {
            assert!(is_periodic_message(&Bytes::from(serialise(msg))));
        }

        // No other direct message types contain a Parsec request or response.
        let msgs = [
            make_message(DirectMessage::BootstrapRequest(rng.gen())),
            make_message(DirectMessage::ConnectionResponse),
        ];
        for msg in &msgs {
            assert!(!is_periodic_message(&Bytes::from(serialise(msg))));
        }

        // A hop message never contains a Parsec message.
        let msg = RoutingMessage {
            src: Authority::Section(rand::random()),
            dst: Authority::Section(rand::random()),
            content: MessageContent::UserMessage(vec![
                rand::random(),
                rand::random(),
                rand::random(),
            ]),
        };
        let msg = SignedRoutingMessage::insecure(msg);
        let msg = unwrap!(HopMessage::new(msg));
        let msg = Message::Hop(msg);
        assert!(!is_periodic_message(&Bytes::from(serialise(&msg))));
    }
}
