// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{super::test_utils, *};
use crate::{messages::RoutingMessage, parsec::generate_bls_threshold_secret_key, unwrap};
use mock_quic_p2p::Network;
use std::collections::BTreeMap;

const ELDER_SIZE: usize = 3;
const NETWORK_PARAMS: NetworkParams = NetworkParams {
    elder_size: ELDER_SIZE,
    safe_section_size: ELDER_SIZE + 1,
};

struct AdultUnderTest {
    adult: Adult,
    elders: BTreeMap<XorName, Chain>,
}

impl AdultUnderTest {
    fn new() -> Self {
        let mut rng = rng::new();
        let network = Network::new();

        let secret_key_set = generate_bls_threshold_secret_key(&mut rng, ELDER_SIZE);
        let public_key_set = secret_key_set.public_keys();

        let (elders_info, _) = test_utils::create_elders_info(&mut rng, &network, ELDER_SIZE);
        let elders = elders_info
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
            .collect();

        let adult = new_adult_state(&mut rng, &network, elders_info, public_key_set);

        Self { adult, elders }
    }

    fn gen_pfx_info_on_parsec_prune(&self, parsec_version: u64) -> GenesisPfxInfo {
        let elder = unwrap!(self.elders.values().next());
        test_utils::create_gen_pfx_info(
            elder.our_info().clone(),
            elder.our_section_bls_keys().clone(),
            parsec_version,
        )
    }

    fn genesis_update_message(&self, gen_pfx_info: GenesisPfxInfo) -> SignedRoutingMessage {
        let msg = RoutingMessage {
            src: Authority::PrefixSection(Prefix::default()),
            dst: Authority::Node(*self.adult.name()),
            content: MessageContent::GenesisUpdate(gen_pfx_info),
        };

        let mut msg = unwrap!(self
            .elders
            .values()
            .take(2)
            .map(|chain| {
                let secret_key = unwrap!(chain.our_section_bls_secret_key_share());
                let public_key_set = chain.our_section_bls_keys().clone();
                let proof = chain.prove(&msg.dst, None);

                unwrap!(SignedRoutingMessage::new(
                    msg.clone(),
                    secret_key,
                    public_key_set,
                    proof
                ))
            })
            .fold(None, |acc, msg| match acc {
                None => Some(msg),
                Some(mut acc) => {
                    acc.add_signature_shares(msg);
                    Some(acc)
                }
            }));
        msg.combine_signatures();
        msg
    }
}

fn new_adult_state(
    rng: &mut MainRng,
    network: &Network,
    elders_info: EldersInfo,
    public_key_set: bls::PublicKeySet,
) -> Adult {
    let first_ages = test_utils::elder_age_counters(elders_info.member_ids());

    let gen_pfx_info = GenesisPfxInfo {
        first_info: elders_info,
        first_bls_keys: public_key_set,
        first_state_serialized: Vec::new(),
        first_ages,
        latest_info: EldersInfo::default(),
        parsec_version: 0,
    };

    let full_id = FullId::gen(rng);

    let details = AdultDetails {
        network_service: test_utils::create_network_service(network),
        event_backlog: Vec::new(),
        full_id,
        gen_pfx_info,
        routing_msg_backlog: Vec::new(),
        direct_msg_backlog: Vec::new(),
        sig_accumulator: Default::default(),
        routing_msg_filter: Default::default(),
        timer: test_utils::create_timer(),
        network_cfg: NETWORK_PARAMS,
        rng: rng::new_from(rng),
    };

    unwrap!(Adult::new(details, Default::default(), &mut ()))
}

#[test]
fn handle_genesis_update_on_parsec_prune() {
    let mut adult_test = AdultUnderTest::new();
    assert_eq!(adult_test.adult.parsec_map.last_version(), 0);

    let gen_pfx_info = adult_test.gen_pfx_info_on_parsec_prune(1);
    match adult_test.adult.handle_genesis_update(gen_pfx_info) {
        Ok(Transition::Stay) => (),
        result => panic!("Unexpected {:?}", result),
    }

    assert_eq!(adult_test.adult.parsec_map.last_version(), 1);
}

#[test]
fn handle_genesis_update_ignore_old_vesions() {
    let mut adult_test = AdultUnderTest::new();

    let gen_pfx_info_1 = adult_test.gen_pfx_info_on_parsec_prune(1);
    let gen_pfx_info_2 = adult_test.gen_pfx_info_on_parsec_prune(2);

    let _ = unwrap!(adult_test
        .adult
        .handle_genesis_update(gen_pfx_info_1.clone()));
    let _ = unwrap!(adult_test.adult.handle_genesis_update(gen_pfx_info_2));
    assert_eq!(adult_test.adult.parsec_map.last_version(), 2);

    let _ = unwrap!(adult_test.adult.handle_genesis_update(gen_pfx_info_1));
    assert_eq!(adult_test.adult.parsec_map.last_version(), 2);
}

#[test]
fn handle_genesis_update_allow_skipped_versions() {
    let mut adult_test = AdultUnderTest::new();
    assert_eq!(adult_test.adult.parsec_map.last_version(), 0);

    let gen_pfx_info = adult_test.gen_pfx_info_on_parsec_prune(2);
    let _ = unwrap!(adult_test.adult.handle_genesis_update(gen_pfx_info));
    assert_eq!(adult_test.adult.parsec_map.last_version(), 2);
}

#[test]
fn genesis_update_message_successful_trust_check() {
    let mut adult_test = AdultUnderTest::new();
    let gen_pfx_info = adult_test.gen_pfx_info_on_parsec_prune(1);
    let msg = adult_test.genesis_update_message(gen_pfx_info);

    let _ = unwrap!(adult_test.adult.handle_signed_message(msg));
    assert_eq!(adult_test.adult.parsec_map.last_version(), 1);
}
