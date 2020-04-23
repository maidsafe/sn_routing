// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::utils as test_utils;
use crate::{
    chain::Chain,
    consensus::{generate_bls_threshold_secret_key, GenesisPfxInfo},
    error::Result,
    id::FullId,
    location::DstLocation,
    messages::{AccumulatingMessage, Message, PlainMessage, Variant},
    network_params::NetworkParams,
    node::{Node, NodeConfig},
    rng::{self, MainRng},
    section::EldersInfo,
    xor_space::{Prefix, XorName},
};
use mock_quic_p2p::Network;
use std::net::SocketAddr;

const ELDER_SIZE: usize = 3;
const NETWORK_PARAMS: NetworkParams = NetworkParams {
    elder_size: ELDER_SIZE,
    safe_section_size: ELDER_SIZE + 1,
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

        let elders = create_elders(&mut rng, &network, None);

        let public_key_set = elders[0].chain.our_section_bls_keys().clone();
        let elders_info = elders[0].chain.state().our_info().clone();
        let gen_pfx_info = test_utils::create_gen_pfx_info(elders_info, public_key_set, 0);

        let (subject, ..) = Node::approved(
            NodeConfig {
                network_params: NETWORK_PARAMS,
                ..Default::default()
            },
            gen_pfx_info,
            None,
        );

        Self {
            rng,
            network,
            subject,
            elders,
        }
    }

    fn gen_pfx_info(&self, parsec_version: u64) -> GenesisPfxInfo {
        test_utils::create_gen_pfx_info(
            self.elders[0].chain.state().our_info().clone(),
            self.elders[0].chain.our_section_bls_keys().clone(),
            parsec_version,
        )
    }

    fn perform_elders_change(&mut self) {
        let prev_elders_info = self.elders[0].chain.state().our_info();
        self.elders = create_elders(&mut self.rng, &self.network, Some(prev_elders_info));
    }

    fn handle_genesis_update(&mut self, gen_pfx_info: GenesisPfxInfo) -> Result<()> {
        for elder in &self.elders {
            let msg = genesis_update_message_signature(
                elder,
                *self.subject.name(),
                gen_pfx_info.clone(),
            )?;

            test_utils::handle_message(&mut self.subject, Some(elder.addr), msg)?;
        }

        Ok(())
    }
}

// Simplified representation of the section elder.
struct Elder {
    chain: Chain,
    addr: SocketAddr,
    full_id: FullId,
}

fn create_elders(
    rng: &mut MainRng,
    network: &Network,
    prev_info: Option<&EldersInfo>,
) -> Vec<Elder> {
    let secret_key_set = generate_bls_threshold_secret_key(rng, ELDER_SIZE);
    let public_key_set = secret_key_set.public_keys();
    let (elders_info, full_ids) =
        test_utils::create_elders_info(rng, network, ELDER_SIZE, prev_info);
    let gen_pfx_info = test_utils::create_gen_pfx_info(elders_info, public_key_set, 0);

    full_ids
        .into_iter()
        .enumerate()
        .map(|(index, (_, full_id))| {
            let chain = Chain::new(
                rng,
                NETWORK_PARAMS,
                full_id.clone(),
                gen_pfx_info.clone(),
                Some(secret_key_set.secret_key_share(index)),
            );

            let addr = network.gen_addr();

            Elder {
                chain,
                addr,
                full_id,
            }
        })
        .collect()
}

fn genesis_update_message_signature(
    sender: &Elder,
    dst: XorName,
    gen_pfx_info: GenesisPfxInfo,
) -> Result<Message> {
    let msg = genesis_update_accumulating_message(&sender.chain, dst, gen_pfx_info)?;
    to_message_signature(&sender.full_id, msg)
}

fn genesis_update_accumulating_message(
    sender: &Chain,
    dst: XorName,
    gen_pfx_info: GenesisPfxInfo,
) -> Result<AccumulatingMessage> {
    let content = PlainMessage {
        src: Prefix::default(),
        dst: DstLocation::Node(dst),
        variant: Variant::GenesisUpdate(Box::new(gen_pfx_info)),
    };

    let secret_key = sender.our_section_bls_secret_key_share().unwrap();
    let public_key_set = sender.our_section_bls_keys().clone();
    let proof = sender.prove(&content.dst, None);

    AccumulatingMessage::new(content, secret_key, public_key_set, proof)
}

fn to_message_signature(sender_id: &FullId, msg: AccumulatingMessage) -> Result<Message> {
    let variant = Variant::MessageSignature(Box::new(msg));
    Message::single_src(sender_id, DstLocation::Direct, variant)
}

#[test]
fn handle_genesis_update_on_parsec_prune() {
    let mut env = Env::new();
    assert_eq!(env.subject.parsec_last_version(), 0);

    let gen_pfx_info = env.gen_pfx_info(1);
    env.handle_genesis_update(gen_pfx_info).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 1);
}

#[test]
fn handle_genesis_update_ignore_old_vesions() {
    let mut env = Env::new();

    let gen_pfx_info_1 = env.gen_pfx_info(1);
    let gen_pfx_info_2 = env.gen_pfx_info(2);

    env.handle_genesis_update(gen_pfx_info_1.clone()).unwrap();
    env.handle_genesis_update(gen_pfx_info_2).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);

    env.handle_genesis_update(gen_pfx_info_1).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);
}

#[test]
fn handle_genesis_update_allow_skipped_versions() {
    let mut env = Env::new();
    assert_eq!(env.subject.parsec_last_version(), 0);

    let gen_pfx_info = env.gen_pfx_info(2);
    env.handle_genesis_update(gen_pfx_info).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);
}

#[test]
fn genesis_update_message_successful_trust_check() {
    let mut env = Env::new();
    let gen_pfx_info = env.gen_pfx_info(1);
    let msg = genesis_update_message_signature(&env.elders[0], *env.subject.name(), gen_pfx_info)
        .unwrap();
    test_utils::handle_message(&mut env.subject, Some(env.elders[0].addr), msg).unwrap();
    assert_eq!(env.subject.parsec_last_version(), 1);
}

#[test]
#[should_panic(expected = "Untrusted")]
fn genesis_update_message_failed_trust_check_proof_too_new() {
    let mut env = Env::new();
    env.perform_elders_change();

    let gen_pfx_info = env.gen_pfx_info(1);
    let msg = genesis_update_message_signature(&env.elders[0], *env.subject.name(), gen_pfx_info)
        .unwrap();
    test_utils::handle_message(&mut env.subject, Some(env.elders[0].addr), msg).unwrap();
}
