// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::EldersInfo;
use crate::{
    consensus::Proven,
    xor_space::{Prefix, XorName},
};

/// Helper structure to synchronize the events necessary to update our section.
#[derive(Default)]
pub struct SectionUpdateBarrier {
    our_key: Option<Proven<bls::PublicKey>>,
    our_info: Option<EldersInfo>, // TODO: prove this

    sibling_key: Option<Proven<bls::PublicKey>>,
    sibling_info: Option<EldersInfo>, // TODO: prove this
}

impl SectionUpdateBarrier {
    pub fn handle_key(
        &mut self,
        our_name: &XorName,
        our_prefix: &Prefix<XorName>,
        new_prefix: &Prefix<XorName>,
        new_key: Proven<bls::PublicKey>,
    ) -> Option<SectionUpdateDetails> {
        if new_prefix.matches(our_name) {
            self.our_key = Some(new_key);
        } else {
            self.sibling_key = Some(new_key);
        }

        self.try_get_details(our_prefix)
    }

    pub fn handle_info(
        &mut self,
        our_name: &XorName,
        our_prefix: &Prefix<XorName>,
        new_info: EldersInfo,
    ) -> Option<SectionUpdateDetails> {
        if new_info.prefix.matches(our_name) {
            self.our_info = Some(new_info);
        } else {
            self.sibling_info = Some(new_info);
        }

        self.try_get_details(our_prefix)
    }

    fn try_get_details(&mut self, our_prefix: &Prefix<XorName>) -> Option<SectionUpdateDetails> {
        match (
            self.our_key.take(),
            self.our_info.take(),
            self.sibling_key.take(),
            self.sibling_info.take(),
        ) {
            (Some(our_key), Some(our_info), None, None) if our_info.prefix == *our_prefix => {
                Some(SectionUpdateDetails {
                    our: SectionDetails {
                        key: our_key,
                        info: our_info,
                    },
                    sibling: None,
                })
            }
            (Some(our_key), Some(our_info), Some(sibling_key), Some(sibling_info)) => {
                Some(SectionUpdateDetails {
                    our: SectionDetails {
                        key: our_key,
                        info: our_info,
                    },
                    sibling: Some(SectionDetails {
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
    pub our: SectionDetails,
    pub sibling: Option<SectionDetails>,
}

#[derive(Eq, PartialEq, Debug)]
pub struct SectionDetails {
    pub key: Proven<bls::PublicKey>,
    pub info: EldersInfo,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{self, Proof},
        rng::{self, MainRng},
    };
    use itertools::Itertools;
    use rand::Rng;

    #[test]
    fn simple() {
        let mut rng = rng::new();

        let our_prefix: Prefix<XorName> = "01".parse().unwrap();
        let our_name = our_prefix.substituted_in(rng.gen());

        let old_sk = consensus::test_utils::gen_secret_key(&mut rng);
        let new_key = gen_proven_key(&mut rng, &old_sk);
        let new_info = dummy_elders_info(our_prefix);

        let all_ops = vec![
            Op::Key(our_prefix, new_key.clone()),
            Op::Info(new_info.clone()),
        ];

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

        let our_prefix: Prefix<XorName> = "01".parse().unwrap();

        let old_sk = consensus::test_utils::gen_secret_key(&mut rng);
        let our_new_key = gen_proven_key(&mut rng, &old_sk);
        let our_new_prefix = our_prefix.pushed(rng.gen());
        let our_new_info = dummy_elders_info(our_new_prefix);

        let sibling_new_key = gen_proven_key(&mut rng, &old_sk);
        let sibling_new_prefix = our_new_prefix.sibling();
        let sibling_new_info = dummy_elders_info(sibling_new_prefix);

        let our_name = our_new_prefix.substituted_in(rng.gen());

        let all_ops = vec![
            Op::Key(our_new_prefix, our_new_key.clone()),
            Op::Key(sibling_new_prefix, sibling_new_key.clone()),
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
        Key(Prefix<XorName>, Proven<bls::PublicKey>),
        Info(EldersInfo),
    }

    fn execute(
        our_name: &XorName,
        our_prefix: &Prefix<XorName>,
        ops: Vec<Op>,
    ) -> Option<SectionUpdateDetails> {
        let mut barrier = SectionUpdateBarrier::default();
        let mut output = None;
        for op in ops {
            output = match op {
                Op::Key(new_prefix, new_key) => {
                    barrier.handle_key(our_name, our_prefix, &new_prefix, new_key)
                }
                Op::Info(new_info) => barrier.handle_info(our_name, our_prefix, new_info),
            }
        }

        output
    }

    fn gen_proven_key(rng: &mut MainRng, old_sk: &bls::SecretKey) -> Proven<bls::PublicKey> {
        let new_pk = consensus::test_utils::gen_secret_key(rng).public_key();
        let signature = old_sk.sign(bincode::serialize(&new_pk).unwrap());

        Proven::new(
            new_pk,
            Proof {
                public_key: old_sk.public_key(),
                signature,
            },
        )
    }

    fn dummy_elders_info(prefix: Prefix<XorName>) -> EldersInfo {
        EldersInfo {
            prefix,
            elders: Default::default(),
        }
    }
}
