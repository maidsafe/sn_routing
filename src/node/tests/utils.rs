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
    consensus::GenesisPrefixInfo,
    error::Result,
    id::{FullId, P2pNode},
    messages::{Message, MessageWithBytes},
    node::Node,
    rng::MainRng,
    section::{AgeCounter, EldersInfo, MIN_AGE_COUNTER},
    xor_space::{Prefix, XorName},
};
use mock_quic_p2p::Network;
use std::{collections::BTreeMap, net::SocketAddr};

pub fn create_elders_info(
    rng: &mut MainRng,
    network: &Network,
    elder_size: usize,
    version: u64,
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
            let node = P2pNode::new(*full_id.public_id(), network.gen_addr());
            (*name, node)
        })
        .collect();

    let elders_info = EldersInfo::new(members_map, Prefix::default(), version);
    (elders_info, full_ids)
}

pub fn create_genesis_prefix_info(
    elders_info: EldersInfo,
    public_keys: bls::PublicKeySet,
    parsec_version: u64,
) -> GenesisPrefixInfo {
    let ages = elder_age_counters(elders_info.elders.keys());

    GenesisPrefixInfo {
        elders_info,
        public_keys,
        state_serialized: Vec::new(),
        ages,
        parsec_version,
    }
}

pub fn elder_age_counters<'a, I>(elders: I) -> BTreeMap<XorName, AgeCounter>
where
    I: IntoIterator<Item = &'a XorName>,
{
    elders
        .into_iter()
        .map(|name| (*name, MIN_AGE_COUNTER))
        .collect()
}

pub fn handle_message(node: &mut Node, sender: Option<SocketAddr>, msg: Message) -> Result<()> {
    let msg = MessageWithBytes::new(msg)?;
    node.try_handle_message(sender, msg)?;
    node.handle_messages();
    Ok(())
}
