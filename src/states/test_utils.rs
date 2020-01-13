// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chain::{AgeCounter, EldersInfo, GenesisPfxInfo, MIN_AGE_COUNTER},
    id::{FullId, P2pNode, PublicId},
    network_service::{NetworkBuilder, NetworkService},
    rng::MainRng,
    timer::Timer,
    unwrap,
    xor_space::{Prefix, XorName},
    ConnectionInfo, NetworkConfig,
};
use crossbeam_channel as mpmc;
use mock_quic_p2p::Network;
use std::{collections::BTreeMap, iter};

pub fn create_network_service(network: &Network) -> NetworkService {
    let endpoint = network.gen_addr();
    let network_config = NetworkConfig::node().with_hard_coded_contact(endpoint);
    let (network_tx, _) = mpmc::unbounded();

    unwrap!(NetworkBuilder::new(network_tx)
        .with_config(network_config)
        .build())
}

pub fn create_timer() -> Timer {
    let (action_tx, _) = mpmc::unbounded();
    Timer::new(action_tx)
}

pub fn create_elders_info(
    rng: &mut MainRng,
    network: &Network,
    elder_size: usize,
) -> (EldersInfo, BTreeMap<XorName, FullId>) {
    let full_ids: BTreeMap<_, _> = (0..elder_size)
        .map(|_| {
            let id = FullId::gen(rng);
            let name = *id.public_id().name();
            (name, id)
        })
        .collect();

    let members_map: BTreeMap<_, _> = full_ids
        .iter()
        .map(|(name, full_id)| {
            let connection_info = ConnectionInfo::from(network.gen_addr());
            let node = P2pNode::new(*full_id.public_id(), connection_info);
            (*name, node)
        })
        .collect();

    let elders_info = unwrap!(EldersInfo::new(
        members_map,
        Prefix::default(),
        iter::empty()
    ));
    (elders_info, full_ids)
}

pub fn create_gen_pfx_info(
    elders_info: EldersInfo,
    public_key_set: bls::PublicKeySet,
    parsec_version: u64,
) -> GenesisPfxInfo {
    let first_ages = elder_age_counters(elders_info.member_ids());

    GenesisPfxInfo {
        first_info: elders_info,
        first_bls_keys: public_key_set,
        first_state_serialized: Vec::new(),
        first_ages,
        latest_info: EldersInfo::default(),
        parsec_version,
    }
}

pub fn elder_age_counters<'a, I>(elders: I) -> BTreeMap<PublicId, AgeCounter>
where
    I: IntoIterator<Item = &'a PublicId>,
{
    elders
        .into_iter()
        .map(|id| (*id, MIN_AGE_COUNTER))
        .collect()
}
