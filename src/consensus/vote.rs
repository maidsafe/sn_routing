// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AccumulationError, Proof, ProofShare, SignatureAggregator};
use crate::{
    error::Result,
    section::{EldersInfo, MemberInfo},
};
use serde::{Serialize, Serializer};
use xor_name::{Prefix, XorName};

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Vote {
    /// Voted for node that is about to join our section
    Online {
        member_info: MemberInfo,
        /// Previous name if relocated.
        previous_name: Option<XorName>,
        /// The key of the destination section that the joining node knows, if any.
        their_knowledge: Option<bls::PublicKey>,
    },

    /// Voted for node we no longer consider online.
    Offline(MemberInfo),

    // Voted to update the elders info of a section.
    SectionInfo(EldersInfo),

    // Voted to update our section key.
    OurKey {
        // In case of split, this prefix is used to differentiate the subsections. It's not part of
        // the proof and thus not serialised when signing.
        prefix: Prefix,
        key: bls::PublicKey,
    },

    // Voted to update their section key.
    TheirKey {
        prefix: Prefix,
        key: bls::PublicKey,
    },

    // Voted to update their knowledge of our section.
    TheirKnowledge {
        prefix: Prefix,
        key_index: u64,
    },

    // Voted to change the age of the given node.
    ChangeAge(MemberInfo),
}

impl Vote {
    /// Create ProofShare for this vote.
    pub fn prove(
        &self,
        public_key_set: bls::PublicKeySet,
        index: usize,
        secret_key_share: &bls::SecretKeyShare,
    ) -> Result<ProofShare> {
        Ok(ProofShare::new(
            public_key_set,
            index,
            secret_key_share,
            &bincode::serialize(&SignableView(self))?,
        ))
    }
}

// Accumulator of `Vote`s.
#[derive(Default)]
pub struct VoteAccumulator(SignatureAggregator<SignableWrapper>);

impl VoteAccumulator {
    pub fn add(
        &mut self,
        vote: Vote,
        proof_share: ProofShare,
    ) -> Result<(Vote, Proof), AccumulationError> {
        self.0
            .add(SignableWrapper(vote), proof_share)
            .map(|(vote, proof)| (vote.0, proof))
    }
}

#[derive(Debug)]
struct SignableWrapper(Vote);

impl Serialize for SignableWrapper {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SignableView(&self.0).serialize(serializer)
    }
}

// View of a `Vote` that can be serialized for the purpose of signing.
struct SignableView<'a>(&'a Vote);

impl<'a> Serialize for SignableView<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Vote::Online { member_info, .. } => member_info.serialize(serializer),
            Vote::Offline(member_info) => member_info.serialize(serializer),
            Vote::SectionInfo(info) => info.serialize(serializer),
            Vote::OurKey { key, .. } => key.serialize(serializer),
            Vote::TheirKey { prefix, key } => (prefix, key).serialize(serializer),
            Vote::TheirKnowledge { prefix, key_index } => (prefix, key_index).serialize(serializer),
            Vote::ChangeAge(member_info) => member_info.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus,
        rng::{self, MainRng},
        section,
    };
    use rand::Rng;
    use std::fmt::Debug;

    #[test]
    fn serialize_for_signing() {
        let mut rng = rng::new();

        // Vote::SectionInfo
        let (elders_info, _) = section::gen_elders_info(&mut rng, Default::default(), 4);
        let vote = Vote::SectionInfo(elders_info.clone());
        verify_serialize_for_signing(&vote, &elders_info);

        // Vote::OurKey
        let prefix = gen_prefix(&mut rng);
        let key = consensus::test_utils::gen_secret_key(&mut rng).public_key();
        let vote = Vote::OurKey { prefix, key };
        verify_serialize_for_signing(&vote, &key);

        // Vote::TheirKey
        let prefix = gen_prefix(&mut rng);
        let key = consensus::test_utils::gen_secret_key(&mut rng).public_key();
        let vote = Vote::TheirKey { prefix, key };
        verify_serialize_for_signing(&vote, &(prefix, key));

        // Vote::TheirKnowledge
        let prefix = gen_prefix(&mut rng);
        let key_index = rng.gen();
        let vote = Vote::TheirKnowledge { prefix, key_index };
        verify_serialize_for_signing(&vote, &(prefix, key_index));
    }

    // Verify that `SignableView(vote)` serializes the same as `should_serialize_as`.
    fn verify_serialize_for_signing<T>(vote: &Vote, should_serialize_as: &T)
    where
        T: Serialize + Debug,
    {
        let actual = bincode::serialize(&SignableView(vote)).unwrap();
        let expected = bincode::serialize(should_serialize_as).unwrap();

        assert_eq!(
            actual, expected,
            "expected SignableView({:?}) to serialize same as {:?}, but didn't",
            vote, should_serialize_as
        )
    }

    fn gen_prefix(rng: &mut MainRng) -> Prefix {
        let mut prefix = Prefix::default();
        let len = rng.gen_range(0, 5);

        for _ in 0..len {
            prefix = prefix.pushed(rng.gen());
        }

        prefix
    }
}
