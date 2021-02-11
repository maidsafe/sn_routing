// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Proof, ProofShare, Proven, SignatureAggregator};
use crate::{
    error::Result,
    messages::PlainMessage,
    section::{EldersInfo, MemberInfo, SectionChain},
};
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;
use xor_name::{Prefix, XorName};

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Vote {
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

    // Voted to update the elders in our section.
    // NOTE: the `EldersInfo` is already signed with the new key. This vote is only to signs the
    // new key with the current key. That way, when it accumulates, we obtain all the following
    // pieces of information at the same time:
    //   1. the new elders info
    //   2. the new key
    //   3. the signature of the new elders info using the new key
    //   4. the signature of the new key using the current key
    // Which we can use to update the section elders info and the section chain at the same time as
    // a single atomic operation without needing to cache anything.
    OurElders(Proven<EldersInfo>),

    // Voted to update their section key.
    TheirKey {
        prefix: Prefix,
        key: bls::PublicKey,
    },

    // Voted to update their knowledge of our section.
    TheirKnowledge {
        prefix: Prefix,
        key: bls::PublicKey,
    },

    // Voted to send an user message whose source is our section.
    SendMessage {
        message: Box<PlainMessage>,
        proof_chain: SectionChain,
    },

    // Voted to concensus whether new node shall be allowed to join
    JoinsAllowed(bool),
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

    #[cfg(test)]
    pub fn as_signable(&self) -> SignableView {
        SignableView(self)
    }
}

// View of a `Vote` that can be serialized for the purpose of signing.
pub(crate) struct SignableView<'a>(&'a Vote);

impl<'a> Serialize for SignableView<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Vote::Online { member_info, .. } => member_info.serialize(serializer),
            Vote::Offline(member_info) => member_info.serialize(serializer),
            Vote::SectionInfo(info) => info.serialize(serializer),
            Vote::OurElders(info) => info.proof.public_key.serialize(serializer),
            Vote::TheirKey { prefix, key } => (prefix, key).serialize(serializer),
            Vote::TheirKnowledge { prefix, key } => (prefix, key).serialize(serializer),
            Vote::SendMessage { message, .. } => message.as_signable().serialize(serializer),
            Vote::JoinsAllowed(joins_allowed) => joins_allowed.serialize(serializer),
        }
    }
}

// Accumulator of `Vote`s.
#[derive(Default)]
pub(crate) struct VoteAccumulator(SignatureAggregator);

impl VoteAccumulator {
    pub fn add(
        &mut self,
        vote: Vote,
        proof_share: ProofShare,
    ) -> Result<(Vote, Proof), VoteAccumulationError> {
        let bytes = bincode::serialize(&SignableView(&vote))?;
        let proof = self.0.add(&bytes, proof_share)?;
        Ok((vote, proof))
    }
}

#[derive(Debug, Error)]
pub(crate) enum VoteAccumulationError {
    #[error("failed to aggregate signature shares: {0}")]
    Aggregation(#[from] bls_signature_aggregator::Error),
    #[error("failed to serialize vote: {0}")]
    Serialization(#[from] bincode::Error),
}

#[derive(Debug)]
struct SignableWrapper(Vote);

impl Serialize for SignableWrapper {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SignableView(&self.0).serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus, section};
    use anyhow::Result;
    use rand::Rng;
    use std::fmt::Debug;

    #[test]
    fn serialize_for_signing() -> Result<()> {
        // Vote::SectionInfo
        let (elders_info, _) = section::test_utils::gen_elders_info(Default::default(), 4);
        let vote = Vote::SectionInfo(elders_info.clone());
        verify_serialize_for_signing(&vote, &elders_info);

        // Vote::OurElders
        let new_sk = bls::SecretKey::random();
        let new_pk = new_sk.public_key();
        let proven_elders_info = consensus::test_utils::proven(&new_sk, elders_info)?;
        let vote = Vote::OurElders(proven_elders_info);
        verify_serialize_for_signing(&vote, &new_pk);

        // Vote::TheirKey
        let prefix = gen_prefix();
        let key = bls::SecretKey::random().public_key();
        let vote = Vote::TheirKey { prefix, key };
        verify_serialize_for_signing(&vote, &(prefix, key));

        // Vote::TheirKnowledge
        let prefix = gen_prefix();
        let key = bls::SecretKey::random().public_key();
        let vote = Vote::TheirKnowledge { prefix, key };
        verify_serialize_for_signing(&vote, &(prefix, key));

        Ok(())
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

    fn gen_prefix() -> Prefix {
        let mut rng = rand::thread_rng();
        let mut prefix = Prefix::default();
        let len = rng.gen_range(0, 5);

        for _ in 0..len {
            prefix = prefix.pushed(rng.gen());
        }

        prefix
    }
}
