// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::utils as test_utils;
use crate::{
    consensus::{generate_bls_threshold_secret_key, GenesisPrefixInfo},
    error::Result,
    id::FullId,
    location::DstLocation,
    messages::{AccumulatingMessage, Message, PlainMessage, Variant},
    network_params::NetworkParams,
    node::{Node, NodeConfig},
    rng::{self, MainRng},
    section::{IndexedSecretKeyShare, SectionKeysProvider, SharedState},
    xor_space::{Prefix, XorName},
};
use mock_quic_p2p::Network;
use std::net::SocketAddr;

const ELDER_SIZE: usize = 3;
const NETWORK_PARAMS: NetworkParams = NetworkParams {
    elder_size: ELDER_SIZE,
    recommended_section_size: ELDER_SIZE + 1,
};

struct Env {
    rng: MainRng,
    network: Network,
    subject: Node,
    elders: Vec<Elder>,
}

impl Env {
    fn new() -> Self {
        let mut rng = rng::new();
        let network = Network::new();

        let elders = create_elders(&mut rng, &network, 0);

        let public_key_set = elders[0].section_keys_provider.public_key_set().clone();
        let elders_info = elders[0].state.our_info().clone();
        let genesis_prefix_info =
            test_utils::create_genesis_prefix_info(elders_info, public_key_set, 0);

        let (subject, ..) = Node::approved(
            NodeConfig {
                network_params: NETWORK_PARAMS,
                ..Default::default()
            },
            genesis_prefix_info,
            None,
        );

        Self {
            rng,
            network,
            subject,
            elders,
        }
    }

    fn genesis_prefix_info(&self, parsec_version: u64) -> GenesisPrefixInfo {
        test_utils::create_genesis_prefix_info(
            self.elders[0].state.our_info().clone(),
            self.elders[0]
                .section_keys_provider
                .public_key_set()
                .clone(),
            parsec_version,
        )
    }

    fn perform_elders_change(&mut self) {
        let current_version = self.elders[0].state.our_info().version;
        self.elders = create_elders(&mut self.rng, &self.network, current_version + 1);
    }

    fn handle_genesis_update(&mut self, genesis_prefix_info: GenesisPrefixInfo) -> Result<()> {
        for elder in &self.elders {
            let msg = genesis_update_message_signature(
                elder,
                *self.subject.name(),
                genesis_prefix_info.clone(),
            )?;

            test_utils::handle_message(&mut self.subject, elder.addr, msg)?;
        }

        Ok(())
    }
}

// Simplified representation of the section elder.
struct Elder {
    state: SharedState,
    section_keys_provider: SectionKeysProvider,
    addr: SocketAddr,
    full_id: FullId,
}

fn create_elders(rng: &mut MainRng, network: &Network, version: u64) -> Vec<Elder> {
    let secret_key_set = generate_bls_threshold_secret_key(rng, ELDER_SIZE);
    let public_key_set = secret_key_set.public_keys();
    let (elders_info, full_ids) = test_utils::create_elders_info(rng, network, ELDER_SIZE, version);
    let genesis_prefix_info =
        test_utils::create_genesis_prefix_info(elders_info, public_key_set, 0);

    full_ids
        .into_iter()
        .enumerate()
        .map(|(index, (_, full_id))| {
            let state = SharedState::new(
                genesis_prefix_info.elders_info.clone(),
                genesis_prefix_info.public_keys.public_key(),
            );
            let section_keys_provider = SectionKeysProvider::new(
                genesis_prefix_info.public_keys.clone(),
                Some(IndexedSecretKeyShare::from_set(&secret_key_set, index)),
            );

            let addr = network.gen_addr();

            Elder {
                state,
                section_keys_provider,
                addr,
                full_id,
            }
        })
        .collect()
}

fn genesis_update_message_signature(
    sender: &Elder,
    dst: XorName,
    genesis_prefix_info: GenesisPrefixInfo,
) -> Result<Message> {
    let msg = genesis_update_accumulating_message(sender, dst, genesis_prefix_info)?;
    to_message_signature(&sender.full_id, msg)
}

fn genesis_update_accumulating_message(
    sender: &Elder,
    dst: XorName,
    genesis_prefix_info: GenesisPrefixInfo,
) -> Result<AccumulatingMessage> {
    let secret_key = sender.section_keys_provider.secret_key_share().unwrap();
    let public_key_set = sender.section_keys_provider.public_key_set().clone();

    let content = PlainMessage {
        src: Prefix::default(),
        dst: DstLocation::Node(dst),
        dst_key: public_key_set.public_key(),
        variant: Variant::GenesisUpdate(Box::new(genesis_prefix_info)),
    };

    let proof = sender.state.prove(&content.dst, None);

    AccumulatingMessage::new(content, secret_key, public_key_set, proof)
}

fn to_message_signature(sender_id: &FullId, msg: AccumulatingMessage) -> Result<Message> {
    let variant = Variant::MessageSignature(Box::new(msg));
    Message::single_src(sender_id, DstLocation::Direct, None, variant)
}

#[test]
fn handle_genesis_update_on_parsec_prune() {
    let mut env = Env::new();
    assert_eq!(env.subject.parsec_last_version(), 0);

    let genesis_prefix_info = env.genesis_prefix_info(1);
    env.handle_genesis_update(genesis_prefix_info).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 1);
}

#[test]
fn handle_genesis_update_ignore_old_vesions() {
    let mut env = Env::new();

    let genesis_prefix_info_1 = env.genesis_prefix_info(1);
    let genesis_prefix_info_2 = env.genesis_prefix_info(2);

    env.handle_genesis_update(genesis_prefix_info_1.clone())
        .unwrap();
    env.handle_genesis_update(genesis_prefix_info_2).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);

    env.handle_genesis_update(genesis_prefix_info_1).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);
}

#[test]
fn handle_genesis_update_allow_skipped_versions() {
    let mut env = Env::new();
    assert_eq!(env.subject.parsec_last_version(), 0);

    let genesis_prefix_info = env.genesis_prefix_info(2);
    env.handle_genesis_update(genesis_prefix_info).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);
}

#[test]
fn genesis_update_message_successful_trust_check() {
    let mut env = Env::new();
    let genesis_prefix_info = env.genesis_prefix_info(1);
    let msg =
        genesis_update_message_signature(&env.elders[0], *env.subject.name(), genesis_prefix_info)
            .unwrap();
    test_utils::handle_message(&mut env.subject, env.elders[0].addr, msg).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 1);
}

#[test]
#[should_panic(expected = "Untrusted")]
fn genesis_update_message_failed_trust_check_proof_too_new() {
    let mut env = Env::new();
    env.perform_elders_change();

    let genesis_prefix_info = env.genesis_prefix_info(1);
    let msg =
        genesis_update_message_signature(&env.elders[0], *env.subject.name(), genesis_prefix_info)
            .unwrap();
    test_utils::handle_message(&mut env.subject, env.elders[0].addr, msg).unwrap();
}
