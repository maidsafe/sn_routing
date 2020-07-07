// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::utils::{self as test_utils, MockTransport};
use crate::{
    consensus::{self, Proven},
    error::Result,
    id::FullId,
    location::DstLocation,
    messages::{AccumulatingMessage, Message, PlainMessage, Variant},
    network_params::NetworkParams,
    node::{Node, NodeConfig},
    rng::{self, MainRng},
    section::{self, EldersInfo, SectionKeyShare, SectionKeysProvider, SharedState},
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
    sk_set: bls::SecretKeySet,
}

impl Env {
    fn new() -> Self {
        let mut rng = rng::new();
        let network = Network::new();

        let (elders_info, full_ids) =
            test_utils::create_elders_info(&mut rng, &network, ELDER_SIZE);
        let sk_set = consensus::generate_secret_key_set(&mut rng, ELDER_SIZE);
        let elders_info = test_utils::create_proven(&sk_set, elders_info);
        let elders = create_elders(&sk_set, elders_info.clone(), full_ids);

        let shared_state = SharedState::new(elders_info);

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
            sk_set,
        }
    }

    fn poll(&mut self) {
        self.network.poll(&mut self.rng)
    }

    fn perform_elders_change(&mut self) {
        let elders_info = self.elders[0].state.our_info().clone();
        let full_ids = self
            .elders
            .drain(..)
            .map(|elder| (*elder.full_id.public_id().name(), elder.full_id))
            .collect();

        let new_sk_set = consensus::generate_secret_key_set(&mut self.rng, ELDER_SIZE);
        let elders_info = test_utils::create_proven(&new_sk_set, elders_info);

        self.elders = create_elders(&new_sk_set, elders_info, full_ids);
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

    fn send_elders_update(
        &mut self,
        sender_full_id: &FullId,
        elders_info: EldersInfo,
        parsec_version: u64,
    ) -> Result<()> {
        let pk = self.sk_set.public_keys().public_key();
        let sender = *elders_info
            .elders
            .get(sender_full_id.public_id().name())
            .unwrap()
            .peer_addr();

        let elders_info = test_utils::create_proven(&self.sk_set, elders_info);
        let variant = Variant::EldersUpdate {
            elders_info,
            parsec_version,
        };
        let message = Message::single_src(sender_full_id, DstLocation::Direct, Some(pk), variant)?;

        test_utils::handle_message(&mut self.subject, sender, message)
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
    sk_set: &bls::SecretKeySet,
    elders_info: Proven<EldersInfo>,
    full_ids: BTreeMap<XorName, FullId>,
) -> Vec<Elder> {
    let pk_set = sk_set.public_keys();

    full_ids
        .into_iter()
        .enumerate()
        .map(|(index, (_, full_id))| {
            let state = SharedState::new(elders_info.clone());

            let section_keys_provider = SectionKeysProvider::new(Some(SectionKeyShare {
                public_key_set: pk_set.clone(),
                index,
                secret_key_share: sk_set.secret_key_share(index),
            }));

            let addr = elders_info
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

#[test]
fn handle_elders_update_on_parsec_prune() {
    let mut env = Env::new();

    let (elders_info, full_ids) =
        section::gen_elders_info(&mut env.rng, Default::default(), ELDER_SIZE);

    assert_eq!(env.subject.parsec_last_version(), 0);

    env.send_elders_update(&full_ids[0], elders_info, 1)
        .unwrap();
    assert_eq!(env.subject.parsec_last_version(), 1);
}

#[test]
fn handle_elders_update_on_elders_change() {
    let mut env = Env::new();

    let old_pk = env.subject.section_key().copied();

    let (elders_info, full_ids) =
        section::gen_elders_info(&mut env.rng, Default::default(), ELDER_SIZE);

    let new_sk_set = consensus::generate_secret_key_set(&mut env.rng, ELDER_SIZE);
    let new_pk = new_sk_set.public_keys().public_key();

    env.sk_set = new_sk_set;
    env.send_elders_update(&full_ids[0], elders_info, 1)
        .unwrap();

    assert_eq!(env.subject.parsec_last_version(), 1);
    assert_ne!(env.subject.section_key(), old_pk.as_ref());
    assert_eq!(env.subject.section_key(), Some(&new_pk));
}

#[test]
fn handle_elders_update_ignore_old_parsec_vesions() {
    let mut env = Env::new();

    let (elders_info, full_ids) =
        section::gen_elders_info(&mut env.rng, Default::default(), ELDER_SIZE);

    env.send_elders_update(&full_ids[0], elders_info.clone(), 1)
        .unwrap();
    assert_eq!(env.subject.parsec_last_version(), 1);

    env.send_elders_update(&full_ids[0], elders_info.clone(), 2)
        .unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);

    env.send_elders_update(&full_ids[0], elders_info, 1)
        .unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);
}

#[test]
fn handle_elders_update_allow_skipped_parsec_versions() {
    let mut env = Env::new();

    assert_eq!(env.subject.parsec_last_version(), 0);

    let (elders_info, full_ids) =
        section::gen_elders_info(&mut env.rng, Default::default(), ELDER_SIZE);

    env.send_elders_update(&full_ids[0], elders_info, 2)
        .unwrap();
    assert_eq!(env.subject.parsec_last_version(), 2);
}

/*
#[test]
fn genesis_update_message_proof_too_new() {
    let mut env = Env::new();
    env.perform_elders_change();

    let genesis_prefix_info = env.genesis_prefix_info(1);
    env.handle_genesis_update(genesis_prefix_info).unwrap();

    // The GenesisUpdate message is bounced so nothing is updated yet.
    assert_eq!(env.subject.parsec_last_version(), 0);
}
*/

#[test]
#[ignore] //FIXME No more StartDkg message, hence no BouncedUnknownMessage
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

/*
#[test]
#[ignore] //FIXME No more StartDkg message, hence no BouncedUntrustedMessage
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
*/
