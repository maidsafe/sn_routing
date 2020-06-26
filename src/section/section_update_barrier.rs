// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::EldersInfo;
use crate::consensus::Proven;

use xor_name::{Prefix, XorName};

/// Helper structure to synchronize the events necessary to update our section.
#[derive(Default)]
pub struct SectionUpdateBarrier {
    our_key: Option<Proven<bls::PublicKey>>,
    our_info: Option<Proven<EldersInfo>>,

    sibling_key: Option<Proven<(Prefix, bls::PublicKey)>>,
    sibling_info: Option<Proven<EldersInfo>>,
}

impl SectionUpdateBarrier {
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

    fn try_get_details(&mut self, our_prefix: &Prefix) -> Option<SectionUpdateDetails> {
        match (
            self.our_key.take(),
            self.our_info.take(),
            self.sibling_key.take(),
            self.sibling_info.take(),
        ) {
            (Some(our_key), Some(our_info), None, None) if our_info.value.prefix == *our_prefix => {
                Some(SectionUpdateDetails {
                    our: OurDetails {
                        key: our_key,
                        info: our_info,
                    },
                    sibling: None,
                })
            }
            (Some(our_key), Some(our_info), Some(sibling_key), Some(sibling_info)) => {
                Some(SectionUpdateDetails {
                    our: OurDetails {
                        key: our_key,
                        info: our_info,
                    },
                    sibling: Some(SiblingDetails {
                        key: sibling_key,
                        info: sibling_info,
                    }),
                })
            }
            (our_key, our_info, sibling_key, sibling_info) => {
                self.our_key = our_key;
                self.our_info = our_info;
                self.sibling_key = sibling_key;
                self.sibling_info = sibling_info;
                None
            }
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct SectionUpdateDetails {
    pub our: OurDetails,
    pub sibling: Option<SiblingDetails>,
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
        let our_new_key = test_utils::gen_secret_key(&mut rng).public_key();
        let our_new_key = test_utils::proven(&old_sk, our_new_key);
        let our_new_info = dummy_elders_info(our_new_prefix);
        let our_new_info = test_utils::proven(&old_sk, our_new_info);

        let sibling_new_prefix = our_new_prefix.sibling();
        let sibling_new_key = test_utils::gen_secret_key(&mut rng).public_key();
        let sibling_new_key = test_utils::proven(&old_sk, (sibling_new_prefix, sibling_new_key));
        let sibling_new_info = dummy_elders_info(sibling_new_prefix);
        let sibling_new_info = test_utils::proven(&old_sk, sibling_new_info);

        let our_name = our_new_prefix.substituted_in(rng.gen());

        let all_ops = vec![
            Op::OurKey(our_new_key.clone()),
            Op::TheirKey(sibling_new_key.clone()),
            Op::Info(our_new_info.clone()),
            Op::Info(sibling_new_info.clone()),
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

        for ops in all_ops.into_iter().combinations(4) {
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
        }
    }

    #[derive(Clone, Debug)]
    enum Op {
        OurKey(Proven<bls::PublicKey>),
        TheirKey(Proven<(Prefix, bls::PublicKey)>),
        Info(Proven<EldersInfo>),
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
