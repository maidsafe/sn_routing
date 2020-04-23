// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    consensus::{ConsensusEngine, GenesisPfxInfo},
    id::FullId,
    rng::MainRng,
    section::{SectionKeyShare, SectionKeys, SectionKeysProvider, SharedState},
};

/// Data chain.
pub struct Chain {
    /// The consensus engine.
    pub consensus_engine: ConsensusEngine,
    /// The section keys provider
    pub section_keys_provider: SectionKeysProvider,
    /// The shared state of the section.
    pub state: SharedState,
}

#[allow(clippy::len_without_is_empty)]
impl Chain {
    /// Returns the shared section state.
    pub fn state(&self) -> &SharedState {
        &self.state
    }

    /// Create a new chain given genesis information
    pub fn new(
        rng: &mut MainRng,
        our_full_id: FullId,
        gen_info: GenesisPfxInfo,
        secret_key_share: Option<bls::SecretKeyShare>,
    ) -> Self {
        // TODO validate `gen_info` to contain adequate proofs
        let our_id = *our_full_id.public_id();

        let secret_key_share = secret_key_share
            .and_then(|key| SectionKeyShare::new(key, &our_id, &gen_info.elders_info));
        let section_keys = SectionKeys {
            public_key_set: gen_info.public_keys.clone(),
            secret_key_share,
        };

        let consensus_engine = ConsensusEngine::new(rng, our_full_id, &gen_info);

        Self {
            section_keys_provider: SectionKeysProvider::new(section_keys),
            state: SharedState::new(gen_info.elders_info, gen_info.public_keys, gen_info.ages),
            consensus_engine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{generate_bls_threshold_secret_key, GenesisPfxInfo},
        id::{FullId, P2pNode, PublicId},
        rng::{self, MainRng},
        section::{EldersInfo, MIN_AGE_COUNTER},
        xor_space::{Prefix, XorName},
    };
    use rand::{seq::SliceRandom, Rng};
    use std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
    };

    enum SecInfoGen<'a> {
        New(Prefix<XorName>, usize),
        Add(&'a EldersInfo),
        Remove(&'a EldersInfo),
    }

    fn gen_section_info(
        rng: &mut MainRng,
        gen: SecInfoGen,
    ) -> (EldersInfo, HashMap<PublicId, FullId>) {
        match gen {
            SecInfoGen::New(pfx, n) => {
                let mut full_ids = HashMap::new();
                let mut members = BTreeMap::new();
                for _ in 0..n {
                    let some_id = FullId::within_range(rng, &pfx.range_inclusive());
                    let peer_addr = ([127, 0, 0, 1], 9999).into();
                    let pub_id = *some_id.public_id();
                    let _ = members.insert(*pub_id.name(), P2pNode::new(pub_id, peer_addr));
                    let _ = full_ids.insert(*some_id.public_id(), some_id);
                }
                (EldersInfo::new(members, pfx, None).unwrap(), full_ids)
            }
            SecInfoGen::Add(info) => {
                let mut members = info.member_map().clone();
                let some_id = FullId::within_range(rng, &info.prefix().range_inclusive());
                let peer_addr = ([127, 0, 0, 1], 9999).into();
                let pub_id = *some_id.public_id();
                let _ = members.insert(*pub_id.name(), P2pNode::new(pub_id, peer_addr));
                let mut full_ids = HashMap::new();
                let _ = full_ids.insert(pub_id, some_id);
                (
                    EldersInfo::new(members, *info.prefix(), Some(info)).unwrap(),
                    full_ids,
                )
            }
            SecInfoGen::Remove(info) => {
                let members = info.member_map().clone();
                (
                    EldersInfo::new(members, *info.prefix(), Some(info)).unwrap(),
                    Default::default(),
                )
            }
        }
    }

    fn add_neighbour_elders_info(chain: &mut Chain, our_id: &PublicId, neighbour_info: EldersInfo) {
        assert!(
            !neighbour_info.prefix().matches(our_id.name()),
            "Only add neighbours."
        );
        chain.state.sections.add_neighbour(neighbour_info)
    }

    fn gen_chain<T>(
        rng: &mut MainRng,
        sections: T,
    ) -> (
        Chain,
        PublicId,
        HashMap<PublicId, FullId>,
        bls::SecretKeySet,
    )
    where
        T: IntoIterator<Item = (Prefix<XorName>, usize)>,
    {
        let mut full_ids = HashMap::new();
        let mut our_id = None;
        let mut section_members = vec![];
        for (pfx, size) in sections {
            let (info, ids) = gen_section_info(rng, SecInfoGen::New(pfx, size));
            if our_id.is_none() {
                our_id = ids.values().next().cloned();
            }
            full_ids.extend(ids);
            section_members.push(info);
        }

        let our_id = our_id.expect("our id");
        let our_pub_id = *our_id.public_id();
        let mut sections_iter = section_members.into_iter();

        let elders_info = sections_iter.next().expect("section members");
        let ages = elders_info
            .member_ids()
            .map(|pub_id| (*pub_id, MIN_AGE_COUNTER))
            .collect();

        let participants = elders_info.len();
        let our_id_index = 0;
        let secret_key_set = generate_bls_threshold_secret_key(rng, participants);
        let secret_key_share = secret_key_set.secret_key_share(our_id_index);
        let public_key_set = secret_key_set.public_keys();

        let genesis_info = GenesisPfxInfo {
            elders_info,
            public_keys: public_key_set,
            state_serialized: Vec::new(),
            ages,
            parsec_version: 0,
        };

        let mut chain = Chain::new(rng, our_id, genesis_info, Some(secret_key_share));

        for neighbour_info in sections_iter {
            add_neighbour_elders_info(&mut chain, &our_pub_id, neighbour_info);
        }

        (chain, our_pub_id, full_ids, secret_key_set)
    }

    fn gen_00_chain(
        rng: &mut MainRng,
    ) -> (
        Chain,
        PublicId,
        HashMap<PublicId, FullId>,
        bls::SecretKeySet,
    ) {
        let elder_size: usize = 7;
        gen_chain(
            rng,
            vec![
                (Prefix::from_str("00").unwrap(), elder_size),
                (Prefix::from_str("01").unwrap(), elder_size),
                (Prefix::from_str("10").unwrap(), elder_size),
            ],
        )
    }

    fn check_infos_for_duplication(chain: &Chain) {
        let mut prefixes: Vec<Prefix<XorName>> = vec![];
        for (_, info) in chain.state.sections.all() {
            if let Some(pfx) = prefixes.iter().find(|x| x.is_compatible(info.prefix())) {
                panic!(
                    "Found compatible prefixes! {:?} and {:?}",
                    pfx,
                    info.prefix()
                );
            }
            prefixes.push(*info.prefix());
        }
    }

    #[test]
    fn generate_chain() {
        let mut rng = rng::new();

        let (chain, our_id, _, _) = gen_00_chain(&mut rng);

        assert_eq!(
            chain
                .state
                .sections
                .get(&Prefix::from_str("00").unwrap())
                .map(|info| info.is_member(&our_id)),
            Some(true)
        );
        assert_eq!(
            chain.state.sections.get(&Prefix::from_str("").unwrap()),
            None
        );
        assert!(chain.state.our_history.validate());
        check_infos_for_duplication(&chain);
    }

    #[test]
    fn neighbour_info_cleaning() {
        let mut rng = rng::new();
        let (mut chain, our_id, _, _) = gen_00_chain(&mut rng);
        for _ in 0..100 {
            let (new_info, _new_ids) = {
                let old_info: Vec<_> = chain.state.sections.other().map(|(_, info)| info).collect();
                let info = old_info.choose(&mut rng).expect("neighbour infos");
                if rng.gen_bool(0.5) {
                    gen_section_info(&mut rng, SecInfoGen::Add(info))
                } else {
                    gen_section_info(&mut rng, SecInfoGen::Remove(info))
                }
            };

            add_neighbour_elders_info(&mut chain, &our_id, new_info);
            assert!(chain.state.our_history.validate());
            check_infos_for_duplication(&chain);
        }
    }
}
