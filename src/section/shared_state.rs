// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{EldersInfo, Section};
use crate::{consensus::Proven, network::Network};
use serde::Serialize;
use std::fmt::Debug;
use xor_name::Prefix;

/// Section state that is shared among all elders of a section via consensus.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct SharedState {
    /// Info about our section.
    pub section: Section,
    /// Info about the rest of the network.
    pub network: Network,
}

impl SharedState {
    pub fn update_our_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
        if self.section.update_elders(elders_info) {
            self.network.prune_neighbours(self.section.prefix());
            true
        } else {
            false
        }
    }

    pub fn update_neighbour_info(&mut self, elders_info: Proven<EldersInfo>) -> bool {
        if self.network.update_neighbour_info(elders_info) {
            self.network.prune_neighbours(self.section.prefix());
            true
        } else {
            false
        }
    }

    pub fn update_their_key(&mut self, key: Proven<(Prefix, bls::PublicKey)>) -> bool {
        if key.value.0 == *self.section.prefix() {
            // Ignore our keys. Use `update_our_key` for that.
            return false;
        }

        self.network.update_their_key(key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        consensus,
        crypto::{keypair_within_range, name, Keypair},
        peer::Peer,
        rng::{self, MainRng},
        section::EldersInfo,
        section::SectionProofChain,
        MIN_AGE,
    };

    use rand::{seq::SliceRandom, Rng};
    use std::{
        collections::{BTreeMap, HashMap},
        iter,
        str::FromStr,
    };
    use xor_name::{Prefix, XorName};

    // Note: The following tests were move over from the former `chain` module.

    enum SecInfoGen<'a> {
        New(Prefix, usize),
        Add(&'a EldersInfo),
        Remove(&'a EldersInfo),
    }

    fn gen_section_info(
        rng: &mut MainRng,
        gen: SecInfoGen,
    ) -> (EldersInfo, HashMap<XorName, Keypair>) {
        match gen {
            SecInfoGen::New(prefix, n) => {
                let mut keypairs = HashMap::new();
                let mut members = BTreeMap::new();
                for _ in 0..n {
                    let some_keypair = keypair_within_range(rng, &prefix.range_inclusive());
                    let peer_addr = ([127, 0, 0, 1], 9999).into();
                    let name = name(&some_keypair.public);
                    let _ = members.insert(name, Peer::new(name, peer_addr, MIN_AGE));
                    let _ = keypairs.insert(name, some_keypair);
                }
                (EldersInfo::new(members, prefix), keypairs)
            }
            SecInfoGen::Add(info) => {
                let mut members = info.elders.clone();
                let some_keypair = keypair_within_range(rng, &info.prefix.range_inclusive());
                let peer_addr = ([127, 0, 0, 1], 9999).into();
                let name = name(&some_keypair.public);
                let _ = members.insert(name, Peer::new(name, peer_addr, MIN_AGE));
                let mut keypairs = HashMap::new();
                let _ = keypairs.insert(name, some_keypair);
                (EldersInfo::new(members, info.prefix), keypairs)
            }
            SecInfoGen::Remove(info) => {
                let elders = info.elders.clone();
                (EldersInfo::new(elders, info.prefix), Default::default())
            }
        }
    }

    fn add_neighbour_elders_info(
        state: &mut SharedState,
        our_id: &XorName,
        neighbour_info: Proven<EldersInfo>,
    ) {
        assert!(
            !neighbour_info.value.prefix.matches(our_id),
            "Only add neighbours."
        );
        let _ = state.network.update_neighbour_info(neighbour_info);
    }

    fn gen_state<T>(rng: &mut MainRng, sections: T) -> (SharedState, XorName, bls::SecretKey)
    where
        T: IntoIterator<Item = (Prefix, usize)>,
    {
        let mut our_id = None;
        let mut section_members = vec![];
        for (prefix, size) in sections {
            let (info, ids) = gen_section_info(rng, SecInfoGen::New(prefix, size));
            if our_id.is_none() {
                our_id = ids.keys().next().cloned();
            }

            section_members.push(info);
        }

        let our_pub_id = our_id.expect("our id");
        let mut sections_iter = section_members.into_iter();

        let sk = consensus::test_utils::gen_secret_key(rng);

        let elders_info = sections_iter.next().expect("section members");
        let elders_info = consensus::test_utils::proven(&sk, elders_info);

        let mut state = SharedState {
            section: Section::new(SectionProofChain::new(sk.public_key()), elders_info),
            network: Network::new(),
        };

        for info in sections_iter {
            let info = consensus::test_utils::proven(&sk, info);
            add_neighbour_elders_info(&mut state, &our_pub_id, info);
        }

        (state, our_pub_id, sk)
    }

    fn gen_00_state(rng: &mut MainRng) -> (SharedState, XorName, bls::SecretKey) {
        let elder_size: usize = 7;
        gen_state(
            rng,
            vec![
                (Prefix::from_str("00").unwrap(), elder_size),
                (Prefix::from_str("01").unwrap(), elder_size),
                (Prefix::from_str("10").unwrap(), elder_size),
            ],
        )
    }

    fn check_infos_for_duplication(state: &SharedState) {
        let mut prefixes: Vec<Prefix> = vec![];
        for info in iter::once(state.section.elders_info()).chain(state.network.all()) {
            if let Some(prefix) = prefixes.iter().find(|x| x.is_compatible(&info.prefix)) {
                panic!(
                    "Found compatible prefixes! {:?} and {:?}",
                    prefix, info.prefix
                );
            }
            prefixes.push(info.prefix);
        }
    }

    #[test]
    fn generate_state() {
        let mut rng = rng::new();

        let (state, our_id, _) = gen_00_state(&mut rng);

        assert!(state.section.elders_info().elders.contains_key(&our_id));
        assert_eq!(state.network.get(&Prefix::default()), None);
        assert!(state.section.chain().self_verify());
        check_infos_for_duplication(&state);
    }

    #[test]
    fn neighbour_info_cleaning() {
        let mut rng = rng::new();
        let (mut state, our_id, sk) = gen_00_state(&mut rng);
        for _ in 0..100 {
            let (new_info, _) = {
                let old_info: Vec<_> = state.network.all().collect();
                let info = old_info.choose(&mut rng).expect("neighbour infos");
                if rng.gen_bool(0.5) {
                    gen_section_info(&mut rng, SecInfoGen::Add(info))
                } else {
                    gen_section_info(&mut rng, SecInfoGen::Remove(info))
                }
            };

            let new_info = consensus::test_utils::proven(&sk, new_info);
            add_neighbour_elders_info(&mut state, &our_id, new_info);
            assert!(state.section.chain().self_verify());
            check_infos_for_duplication(&state);
        }
    }
}
