// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::*;
use crate::{
    chain::{AgeCounter, MIN_AGE_COUNTER},
    network_service::NetworkBuilder,
    parsec::generate_bls_threshold_secret_key,
    unwrap, NetworkConfig,
};
use crossbeam_channel as mpmc;
use mock_quic_p2p::Network;
use std::{collections::BTreeMap, iter};

const ELDER_SIZE: usize = 3;

struct AdultUnderTest {
    adult: Adult,
    elders_info: EldersInfo,
    public_key_set: bls::PublicKeySet,
}

impl AdultUnderTest {
    fn new() -> Self {
        let mut rng = rng::new();
        let network = Network::new();

        let elders: BTreeMap<_, _> = (0..ELDER_SIZE)
            .map(|_| {
                let full_id = FullId::gen(&mut rng);
                let connection_info = ConnectionInfo::from(network.gen_addr());
                let name = *full_id.public_id().name();
                let node = P2pNode::new(*full_id.public_id(), connection_info);
                (name, node)
            })
            .collect();
        let elders_info = unwrap!(EldersInfo::new(elders, Prefix::default(), iter::empty()));
        let secret_key_set = generate_bls_threshold_secret_key(&mut rng, ELDER_SIZE);
        let public_key_set = secret_key_set.public_keys();

        let adult = new_adult_state(&mut rng, &network, elders_info.clone(), secret_key_set);

        Self {
            adult,
            elders_info,
            public_key_set,
        }
    }

    fn gen_pfx_info_on_parsec_prune(&self, parsec_version: u64) -> GenesisPfxInfo {
        GenesisPfxInfo {
            first_info: self.elders_info.clone(),
            first_bls_keys: self.public_key_set.clone(),
            first_state_serialized: Vec::new(),
            first_ages: elder_age_counters(self.elders_info.member_ids()),
            latest_info: EldersInfo::default(),
            parsec_version,
        }
    }
}

fn new_adult_state(
    rng: &mut MainRng,
    network: &Network,
    elders_info: EldersInfo,
    secret_key_set: bls::SecretKeySet,
) -> Adult {
    let endpoint = network.gen_addr();
    let network_config = NetworkConfig::node().with_hard_coded_contact(endpoint);
    let (network_tx, _) = mpmc::unbounded();
    let network_service = unwrap!(NetworkBuilder::new(network_tx)
        .with_config(network_config)
        .build());

    let first_ages = elder_age_counters(elders_info.member_ids());

    let gen_pfx_info = GenesisPfxInfo {
        first_info: elders_info,
        first_bls_keys: secret_key_set.public_keys(),
        first_state_serialized: Vec::new(),
        first_ages,
        latest_info: EldersInfo::default(),
        parsec_version: 0,
    };

    let full_id = FullId::gen(rng);

    let (action_tx, _) = mpmc::unbounded();
    let timer = Timer::new(action_tx);

    let details = AdultDetails {
        network_service,
        event_backlog: Vec::new(),
        full_id,
        gen_pfx_info,
        routing_msg_backlog: Vec::new(),
        direct_msg_backlog: Vec::new(),
        sig_accumulator: Default::default(),
        routing_msg_filter: Default::default(),
        timer,
        network_cfg: NetworkParams {
            elder_size: ELDER_SIZE,
            safe_section_size: ELDER_SIZE + 1,
        },
        rng: rng::new_from(rng),
    };

    unwrap!(Adult::new(details, Default::default(), &mut ()))
}

fn elder_age_counters<'a, I>(elders: I) -> BTreeMap<PublicId, AgeCounter>
where
    I: IntoIterator<Item = &'a PublicId>,
{
    elders
        .into_iter()
        .map(|id| (*id, MIN_AGE_COUNTER))
        .collect()
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
