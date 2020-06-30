// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::utils::{self as test_utils, MockTransport};
use crate::{
    consensus::{self, GenesisPrefixInfo},
    error::Result,
    id::FullId,
    location::DstLocation,
    messages::{AccumulatingMessage, Message, PlainMessage, Variant},
    network_params::NetworkParams,
    node::{Node, NodeConfig},
    rng::{self, MainRng},
    section::{EldersInfo, SectionKeyShare, SectionKeysProvider, SharedState},
};

use mock_quic_p2p::Network;
use rand::Rng;
use std::{collections::BTreeMap, net::SocketAddr};
use xor_name::{Prefix, XorName};

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

        let (elders_info, full_ids) =
            test_utils::create_elders_info(&mut rng, &network, ELDER_SIZE);
        let elders = create_elders(&mut rng, elders_info.value.clone(), full_ids);

        let public_key_set = elders[0]
            .section_keys_provider
            .key_share()
            .unwrap()
            .public_key_set
            .clone();
        let public_key = public_key_set.public_key();

        let shared_state = SharedState::new(elders_info, public_key);

        let (subject, ..) = Node::approved(
            NodeConfig {
                network_params: NETWORK_PARAMS,
                ..Default::default()
            },
            shared_state,
            0,
            None,
        );

        Self {
            rng,
            network,
            subject,
            elders,
        }
    }

    fn poll(&mut self) {
        self.network.poll(&mut self.rng)
    }

    fn genesis_prefix_info(&self, parsec_version: u64) -> GenesisPrefixInfo {
        GenesisPrefixInfo {
            elders_info: self.elders[0].state.sections.proven_our().clone(),
            parsec_version,
        }
    }

    fn perform_elders_change(&mut self) {
        let elders_info = self.elders[0].state.our_info().clone();
        let full_ids = self
            .elders
            .drain(..)
            .map(|elder| (*elder.full_id.public_id().name(), elder.full_id))
            .collect();

        self.elders = create_elders(&mut self.rng, elders_info, full_ids);
    }

    fn handle_genesis_update(&mut self, genesis_prefix_info: GenesisPrefixInfo) -> Result<()> {
        for elder in &mut self.elders {
            let msg = create_genesis_update_message_signature(
                elder,
                *self.subject.name(),
                genesis_prefix_info.clone(),
            )?;

            test_utils::handle_message(&mut self.subject, *elder.addr(), msg)?;
        }

        Ok(())
    }

    fn create_user_message(&self, dst: DstLocation, content: Vec<u8>) -> Message {
        let msg = PlainMessage {
            src: Prefix::default(),
            dst,
            dst_key: self.elders[0]
                .section_keys_provider
                .key_share()
                .unwrap()
                .public_key_set
                .public_key(),
            variant: Variant::UserMessage(content),
        };
        self.accumulate_message(msg)
    }

    fn accumulate_message(&self, content: PlainMessage) -> Message {
        test_utils::accumulate_messages(
            self.elders
                .iter()
                .map(|elder| to_accumulating_message(elder, content.clone()).unwrap()),
        )
    }
}

// Simplified representation of the section elder.
struct Elder {
    full_id: FullId,
    state: SharedState,
    section_keys_provider: SectionKeysProvider,
    transport: MockTransport,
}

impl Elder {
    fn addr(&self) -> &SocketAddr {
        self.transport.addr()
    }

    fn received_messages(&self) -> impl Iterator<Item = (SocketAddr, Message)> + '_ {
        self.transport.received_messages()
    }
}

fn create_elders(
    rng: &mut MainRng,
    elders_info: EldersInfo,
    full_ids: BTreeMap<XorName, FullId>,
) -> Vec<Elder> {
    let secret_key_set = consensus::generate_secret_key_set(rng, ELDER_SIZE);
    let public_key_set = secret_key_set.public_keys();
    let public_key = public_key_set.public_key();

    let fake_prev_secret_key = consensus::test_utils::gen_secret_key(rng);
    let elders_info = consensus::test_utils::proven(&fake_prev_secret_key, elders_info);

    let genesis_prefix_info = GenesisPrefixInfo {
        elders_info,
        parsec_version: 0,
    };

    full_ids
        .into_iter()
        .enumerate()
        .map(|(index, (_, full_id))| {
            let state = SharedState::new(genesis_prefix_info.elders_info.clone(), public_key);

            let section_keys_provider = SectionKeysProvider::new(Some(SectionKeyShare {
                public_key_set: public_key_set.clone(),
                index,
                secret_key_share: secret_key_set.secret_key_share(index),
            }));

            let addr = genesis_prefix_info
                .elders_info
                .value
                .elders
                .get(full_id.public_id().name())
                .map(|p2p_node| p2p_node.peer_addr());
            let transport = MockTransport::new(addr);

            Elder {
                full_id,
                state,
                section_keys_provider,
                transport,
            }
        })
        .collect()
}

fn create_genesis_update_message_signature(
    sender: &Elder,
    dst: XorName,
    genesis_prefix_info: GenesisPrefixInfo,
) -> Result<Message> {
    let msg = create_genesis_update_accumulating_message(sender, dst, genesis_prefix_info)?;
    to_message_signature(&sender.full_id, msg)
}

fn create_genesis_update_accumulating_message(
    sender: &Elder,
    dst: XorName,
    genesis_prefix_info: GenesisPrefixInfo,
) -> Result<AccumulatingMessage> {
    let content = PlainMessage {
        src: Prefix::default(),
        dst: DstLocation::Node(dst),
        dst_key: sender
            .section_keys_provider
            .key_share()
            .unwrap()
            .public_key_set
            .public_key(),
        variant: Variant::GenesisUpdate(genesis_prefix_info),
    };

    to_accumulating_message(sender, content)
}

fn to_accumulating_message(sender: &Elder, content: PlainMessage) -> Result<AccumulatingMessage> {
    let key_share = sender.section_keys_provider.key_share().unwrap();
    let proof_chain = sender.state.prove(&content.dst, None);
    let proof_share = content.prove(
        key_share.public_key_set.clone(),
        key_share.index,
        &key_share.secret_key_share,
    )?;

    Ok(AccumulatingMessage::new(content, proof_chain, proof_share))
}

fn to_message_signature(sender_id: &FullId, msg: AccumulatingMessage) -> Result<Message> {
    let variant = Variant::MessageSignature(Box::new(msg));
    Ok(Message::single_src(
        sender_id,
        DstLocation::Direct,
        None,
        variant,
    )?)
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
fn genesis_update_message_proof_too_new() {
    let mut env = Env::new();
    env.perform_elders_change();

    let genesis_prefix_info = env.genesis_prefix_info(1);
    env.handle_genesis_update(genesis_prefix_info).unwrap();

    // The GenesisUpdate message is bounced so nothing is updated yet.
    assert_eq!(env.subject.parsec_last_version(), 0);
}

#[test]
fn handle_unknown_message() {
    let mut env = Env::new();

    let dst = DstLocation::Section(env.rng.gen());
    let msg = env.create_user_message(dst, b"hello section".to_vec());
    test_utils::handle_message(&mut env.subject, *env.elders[0].addr(), msg).unwrap();

    env.poll();

    for (sender, msg) in env.elders[0].received_messages() {
        if sender == env.subject.our_connection_info().unwrap()
            && matches!(msg.variant(), Variant::BouncedUnknownMessage { .. })
        {
            return;
        }
    }

    panic!("BouncedUnknownMessage not received")
}

#[test]
fn handle_untrusted_accumulated_message() {
    let mut env = Env::new();

    // Generate new section key which the adult is not yet aware of.
    env.perform_elders_change();

    // This message is signed with the new key so won't be trusted by the adult yet.
    let dst = DstLocation::Node(*env.subject.name());
    let msg = env.create_user_message(dst, b"hello node".to_vec());
    test_utils::handle_message(&mut env.subject, *env.elders[0].addr(), msg).unwrap();

    env.poll();

    for (sender, msg) in env.elders[0].received_messages() {
        if sender == env.subject.our_connection_info().unwrap()
            && matches!(msg.variant(), Variant::BouncedUntrustedMessage(_))
        {
            return;
        }
    }

    panic!("BouncedUntrustedMessage not received")
}

#[test]
fn handle_untrusted_accumulating_message() {
    let mut env = Env::new();
    env.perform_elders_change();

    // The GenesisUpdate message is accumulated at destination and so is received as a series of
    // `MessageSignature`s.
    let genesis_prefix_info = env.genesis_prefix_info(1);
    env.handle_genesis_update(genesis_prefix_info).unwrap();

    env.poll();

    for (sender, msg) in env.elders[0].received_messages() {
        if sender == env.subject.our_connection_info().unwrap()
            && matches!(msg.variant(), Variant::BouncedUntrustedMessage(_))
        {
            return;
        }
    }

    panic!("BouncedUntrustedMessage not received")
}
