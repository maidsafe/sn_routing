// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::EldersInfo;
use crate::{consensus::Proven, id::P2pNode};

use xor_name::{Prefix, XorName};

/// Helper structure to synchronize the events necessary to update our section.
#[derive(Default)]
pub struct SectionUpdateBarrier {
    our_key: Option<Proven<bls::PublicKey>>,
    our_info: Option<Proven<EldersInfo>>,

    sibling_key: Option<Proven<(Prefix, bls::PublicKey)>>,
    sibling_info: Option<Proven<EldersInfo>>,

    // Sibling's own key
    sibling_our_key: Option<Proven<bls::PublicKey>>,
    // Our key for sibling
    sibling_their_key: Option<Proven<(Prefix, bls::PublicKey)>>,
}

impl SectionUpdateBarrier {
    pub fn handle_sibling_our_key(
        &mut self,
        our_prefix: &Prefix,
        new_key: Proven<bls::PublicKey>,
    ) -> Option<SectionUpdateDetails> {
        self.sibling_our_key = Some(new_key);
        self.try_get_details(our_prefix)
    }

    pub fn handle_sibling_their_key(
        &mut self,
        our_prefix: &Prefix,
        new_key: Proven<(Prefix, bls::PublicKey)>,
    ) -> Option<SectionUpdateDetails> {
        self.sibling_their_key = Some(new_key);
        self.try_get_details(our_prefix)
    }

    pub fn handle_our_key(
        &mut self,
        our_prefix: &Prefix,
        new_key: Proven<bls::PublicKey>,
    ) -> Option<SectionUpdateDetails> {
        self.our_key = Some(new_key);
        self.try_get_details(our_prefix)
    }

    pub fn handle_their_key(
        &mut self,
        our_prefix: &Prefix,
        new_key: Proven<(Prefix, bls::PublicKey)>,
    ) -> Option<SectionUpdateDetails> {
        self.sibling_key = Some(new_key);
        self.try_get_details(our_prefix)
    }

    pub fn handle_info(
        &mut self,
        our_name: &XorName,
        our_prefix: &Prefix,
        new_info: Proven<EldersInfo>,
    ) -> Option<SectionUpdateDetails> {
        if new_info.value.prefix.matches(our_name) {
            self.our_info = Some(new_info);
        } else {
            self.sibling_info = Some(new_info);
        }

        self.try_get_details(our_prefix)
    }

    fn try_get_details(&self, our_prefix: &Prefix) -> Option<SectionUpdateDetails> {
        match (
            self.our_key.clone(),
            self.our_info.clone(),
            self.sibling_key.clone(),
            self.sibling_info.clone(),
            self.sibling_our_key.clone(),
            self.sibling_their_key.clone(),
        ) {
            (Some(our_key), Some(our_info), None, None, None, None)
                if our_info.value.prefix == *our_prefix =>
            {
                Some(SectionUpdateDetails {
                    our: OurDetails {
                        key: our_key,
                        info: our_info,
                    },
                    sibling: None,
                })
            }
            (
                Some(our_key),
                Some(our_info),
                Some(sibling_key),
                Some(sibling_info),
                Some(sibling_our_key),
                Some(sibling_their_key),
            ) => Some(SectionUpdateDetails {
                our: OurDetails {
                    key: our_key,
                    info: our_info,
                },
                sibling: Some(SiblingDetails {
                    key: sibling_key,
                    info: sibling_info,
                    sibling_our_key,
                    sibling_their_key,
                }),
            }),
            _ => None,
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct SectionUpdateDetails {
    pub our: OurDetails,
    pub sibling: Option<SiblingDetails>,
}

impl SectionUpdateDetails {
    // Returns all the nodes that will be elders after this update. In case of a split, returns
    // nodes from both subsections.
    pub fn all_elders(&self) -> impl Iterator<Item = &P2pNode> {
        self.our.info.value.elders.values().chain(
            self.sibling
                .as_ref()
                .into_iter()
                .flat_map(|sibling| sibling.info.value.elders.values()),
        )
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct OurDetails {
    pub key: Proven<bls::PublicKey>,
    pub info: Proven<EldersInfo>,
}

#[derive(Eq, PartialEq, Debug)]
pub struct SiblingDetails {
    pub key: Proven<(Prefix, bls::PublicKey)>,
    pub info: Proven<EldersInfo>,
    pub sibling_our_key: Proven<bls::PublicKey>,
    pub sibling_their_key: Proven<(Prefix, bls::PublicKey)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus::test_utils, rng};
    use itertools::Itertools;
    use rand::Rng;

    #[test]
    fn simple() {
        let mut rng = rng::new();

        let our_prefix: Prefix = "01".parse().unwrap();
        let our_name = our_prefix.substituted_in(rng.gen());

        let old_sk = test_utils::gen_secret_key(&mut rng);
        let new_key = test_utils::gen_secret_key(&mut rng).public_key();
        let new_key = test_utils::proven(&old_sk, new_key);

        let new_info = dummy_elders_info(our_prefix);
        let new_info = test_utils::proven(&old_sk, new_info);

        let all_ops = vec![Op::OurKey(new_key.clone()), Op::Info(new_info.clone())];

        assert_eq!(execute(&our_name, &our_prefix, vec![]), None);

        for ops in all_ops.clone().into_iter().combinations(1) {
            assert_eq!(execute(&our_name, &our_prefix, ops), None);
        }

        for ops in all_ops.into_iter().combinations(2) {
            let details = execute(&our_name, &our_prefix, ops).unwrap();
            assert_eq!(details.our.key, new_key);
            assert_eq!(details.our.info, new_info);
            assert_eq!(details.sibling, None);
        }
    }

    #[test]
    fn split() {
        let mut rng = rng::new();

        let our_prefix: Prefix = "01".parse().unwrap();
        let old_sk = test_utils::gen_secret_key(&mut rng);

        let our_new_prefix = our_prefix.pushed(rng.gen());
        let our_new_public_key = test_utils::gen_secret_key(&mut rng).public_key();
        let our_new_key = test_utils::proven(&old_sk, our_new_public_key);
        let our_new_info = dummy_elders_info(our_new_prefix);
        let our_new_info = test_utils::proven(&old_sk, our_new_info);

        let sibling_new_prefix = our_new_prefix.sibling();
        let sibling_new_public_key = test_utils::gen_secret_key(&mut rng).public_key();
        let sibling_new_key =
            test_utils::proven(&old_sk, (sibling_new_prefix, sibling_new_public_key));
        let sibling_new_info = dummy_elders_info(sibling_new_prefix);
        let sibling_new_info = test_utils::proven(&old_sk, sibling_new_info);

        let sibling_our_key = test_utils::proven(&old_sk, sibling_new_public_key);
        let sibling_their_key = test_utils::proven(&old_sk, (our_new_prefix, our_new_public_key));

        let our_name = our_new_prefix.substituted_in(rng.gen());

        let all_ops = vec![
            Op::OurKey(our_new_key.clone()),
            Op::TheirKey(sibling_new_key.clone()),
            Op::Info(our_new_info.clone()),
            Op::Info(sibling_new_info.clone()),
            Op::SiblingOurKey(sibling_our_key.clone()),
            Op::SiblingTheirKey(sibling_their_key.clone()),
        ];

        assert_eq!(execute(&our_name, &our_prefix, vec![]), None);

        for ops in all_ops.clone().into_iter().combinations(1) {
            assert_eq!(execute(&our_name, &our_prefix, ops), None);
        }

        for ops in all_ops.clone().into_iter().combinations(2) {
            assert_eq!(execute(&our_name, &our_prefix, ops), None);
        }

        for ops in all_ops.clone().into_iter().combinations(3) {
            assert_eq!(execute(&our_name, &our_prefix, ops), None);
        }

        for ops in all_ops.clone().into_iter().combinations(4) {
            assert_eq!(execute(&our_name, &our_prefix, ops), None);
        }

        for ops in all_ops.clone().into_iter().combinations(5) {
            assert_eq!(execute(&our_name, &our_prefix, ops), None);
        }

        for ops in all_ops.into_iter().combinations(6) {
            let details = execute(&our_name, &our_prefix, ops).unwrap();
            assert_eq!(details.our.key, our_new_key);
            assert_eq!(details.our.info, our_new_info);

            assert_eq!(
                details.sibling.as_ref().map(|d| &d.key),
                Some(&sibling_new_key)
            );
            assert_eq!(
                details.sibling.as_ref().map(|d| &d.info),
                Some(&sibling_new_info)
            );

            assert_eq!(
                details.sibling.as_ref().map(|d| &d.sibling_our_key),
                Some(&sibling_our_key)
            );
            assert_eq!(
                details.sibling.as_ref().map(|d| &d.sibling_their_key),
                Some(&sibling_their_key)
            );
        }
    }

    #[derive(Clone, Debug)]
    enum Op {
        OurKey(Proven<bls::PublicKey>),
        TheirKey(Proven<(Prefix, bls::PublicKey)>),
        Info(Proven<EldersInfo>),
        SiblingOurKey(Proven<bls::PublicKey>),
        SiblingTheirKey(Proven<(Prefix, bls::PublicKey)>),
    }

    fn execute(
        our_name: &XorName,
        our_prefix: &Prefix,
        ops: Vec<Op>,
    ) -> Option<SectionUpdateDetails> {
        let mut barrier = SectionUpdateBarrier::default();
        let mut output = None;
        for op in ops {
            output = match op {
                Op::OurKey(new_key) => barrier.handle_our_key(our_prefix, new_key),
                Op::TheirKey(new_key) => barrier.handle_their_key(our_prefix, new_key),
                Op::Info(new_info) => barrier.handle_info(our_name, our_prefix, new_info),
                Op::SiblingOurKey(new_key) => barrier.handle_sibling_our_key(our_prefix, new_key),
                Op::SiblingTheirKey(new_key) => {
                    barrier.handle_sibling_their_key(our_prefix, new_key)
                }
            }
        }

        output
    }

    fn dummy_elders_info(prefix: Prefix) -> EldersInfo {
        EldersInfo {
            prefix,
            elders: Default::default(),
        }
    }
}
