// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{super::super::approved_peer::*, utils as test_utils};
use crate::{
    chain::EldersInfo, id::FullId, messages::AccumulatingMessage, messages::PlainMessage,
    parsec::generate_bls_threshold_secret_key, rng::MainRng,
};
use mock_quic_p2p::Network;
use std::collections::BTreeMap;

const ELDER_SIZE: usize = 3;
const NETWORK_PARAMS: NetworkParams = NetworkParams {
    elder_size: ELDER_SIZE,
    safe_section_size: ELDER_SIZE + 1,
};

struct Env {
    rng: MainRng,
    network: Network,
    subject: ApprovedPeer,
    elders: BTreeMap<XorName, Chain>,
}

impl Env {
    fn new() -> Self {
        let mut rng = rng::new();
        let network = Network::new();

        let elders = create_elders(&mut rng, &network, None);

        let elder = elders.values().next().expect("no elders");
        let public_key_set = elder.our_section_bls_keys().clone();
        let elders_info = elder.our_info().clone();
        let gen_pfx_info = test_utils::create_gen_pfx_info(elders_info, public_key_set, 0);

        let subject = create_state(&mut rng, &network, gen_pfx_info);

        Self {
            rng,
            network,
            subject,
            elders,
        }
    }

    fn gen_pfx_info(&self, parsec_version: u64) -> GenesisPfxInfo {
        let elder = self.elders.values().next().expect("no elders");
        test_utils::create_gen_pfx_info(
            elder.our_info().clone(),
            elder.our_section_bls_keys().clone(),
            parsec_version,
        )
    }

    fn genesis_update_message(&self, gen_pfx_info: GenesisPfxInfo) -> Message {
        let content = PlainMessage {
            src: Prefix::default(),
            dst: DstLocation::Node(*self.subject.name()),
            variant: Variant::GenesisUpdate(Box::new(gen_pfx_info)),
        };

        self.elders
            .values()
            .take(2)
            .map(|chain| {
                let secret_key = chain.our_section_bls_secret_key_share().unwrap();
                let public_key_set = chain.our_section_bls_keys().clone();
                let proof = chain.prove(&content.dst, None);

                AccumulatingMessage::new(content.clone(), secret_key, public_key_set, proof)
                    .unwrap()
            })
            .fold(None, |acc, msg| match acc {
                None => Some(msg),
                Some(mut acc) => {
                    acc.add_signature_shares(msg);
                    Some(acc)
                }
            })
            .and_then(|msg| msg.combine_signatures())
            .expect("failed to accumulate the message")
    }

    fn perform_elders_change(&mut self) {
        let prev_elders_info = self.elders.values().next().expect("no elders").our_info();
        self.elders = create_elders(&mut self.rng, &self.network, Some(prev_elders_info));
    }

    fn handle_message(&mut self, msg: Message) -> Result<()> {
        let msg = MessageWithBytes::new(msg).unwrap();
        let _ = self.subject.try_handle_message(None, msg, &mut ())?;
        let _ = self.subject.handle_messages(&mut ());
        Ok(())
    }
}

fn create_elders(
    rng: &mut MainRng,
    network: &Network,
    prev_info: Option<&EldersInfo>,
) -> BTreeMap<XorName, Chain> {
    let secret_key_set = generate_bls_threshold_secret_key(rng, ELDER_SIZE);
    let public_key_set = secret_key_set.public_keys();
    let (elders_info, _) = test_utils::create_elders_info(rng, network, ELDER_SIZE, prev_info);

    elders_info
        .member_ids()
        .enumerate()
        .map(|(index, id)| {
            let gen_pfx_info =
                test_utils::create_gen_pfx_info(elders_info.clone(), public_key_set.clone(), 0);
            let chain = Chain::new(
                NETWORK_PARAMS,
                *id,
                gen_pfx_info,
                Some(secret_key_set.secret_key_share(index)),
            );
            (*id.name(), chain)
        })
        .collect()
}

fn create_state(
    rng: &mut MainRng,
    network: &Network,
    gen_pfx_info: GenesisPfxInfo,
) -> ApprovedPeer {
    let full_id = FullId::gen(rng);

    let core = Core {
        full_id,
        transport: test_utils::create_transport(network),
        msg_filter: Default::default(),
        msg_queue: Default::default(),
        timer: test_utils::create_timer(),
        rng: rng::new_from(rng),
    };

    let subject = ApprovedPeer::new(
        core,
        NetworkParams::default(),
        Connected::First,
        gen_pfx_info,
        None,
        &mut (),
    );
    assert!(!subject.stage.chain.is_self_elder());
    subject
}

#[test]
fn handle_genesis_update_on_parsec_prune() {
    let mut env = Env::new();
    assert_eq!(env.subject.stage.parsec_map.last_version(), 0);

    let gen_pfx_info = env.gen_pfx_info(1);
    env.subject
        .stage
        .handle_genesis_update(&mut env.subject.core, gen_pfx_info)
        .unwrap();
    assert_eq!(env.subject.stage.parsec_map.last_version(), 1);
}

#[test]
fn handle_genesis_update_ignore_old_vesions() {
    let mut env = Env::new();

    let gen_pfx_info_1 = env.gen_pfx_info(1);
    let gen_pfx_info_2 = env.gen_pfx_info(2);

    env.subject
        .stage
        .handle_genesis_update(&mut env.subject.core, gen_pfx_info_1.clone())
        .unwrap();
    env.subject
        .stage
        .handle_genesis_update(&mut env.subject.core, gen_pfx_info_2)
        .unwrap();
    assert_eq!(env.subject.stage.parsec_map.last_version(), 2);

    env.subject
        .stage
        .handle_genesis_update(&mut env.subject.core, gen_pfx_info_1)
        .unwrap();
    assert_eq!(env.subject.stage.parsec_map.last_version(), 2);
}

#[test]
fn handle_genesis_update_allow_skipped_versions() {
    let mut env = Env::new();
    assert_eq!(env.subject.stage.parsec_map.last_version(), 0);

    let gen_pfx_info = env.gen_pfx_info(2);
    env.subject
        .stage
        .handle_genesis_update(&mut env.subject.core, gen_pfx_info)
        .unwrap();
    assert_eq!(env.subject.stage.parsec_map.last_version(), 2);
}

#[test]
fn genesis_update_message_successful_trust_check() {
    let mut env = Env::new();
    let gen_pfx_info = env.gen_pfx_info(1);
    let msg = env.genesis_update_message(gen_pfx_info);

    env.handle_message(msg).unwrap();
    assert_eq!(env.subject.stage.parsec_map.last_version(), 1);
}

#[test]
#[should_panic(expected = "Untrusted")]
fn genesis_update_message_failed_trust_check_proof_too_new() {
    let mut env = Env::new();
    env.perform_elders_change();

    let gen_pfx_info = env.gen_pfx_info(1);
    let msg = env.genesis_update_message(gen_pfx_info);
    let _ = env.handle_message(msg);
}
