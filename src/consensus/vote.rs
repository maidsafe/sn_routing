// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{AccumulationError, Proof, ProofShare, SignatureAccumulator};
use crate::{error::Result, section::EldersInfo};
use serde::{Serialize, Serializer};
use xor_name::Prefix;

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum Vote {
    // Vote to update the elders info of a section.
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
pub struct VoteAccumulator(SignatureAccumulator<SignableWrapper>);

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
            Vote::SectionInfo(info) => info.serialize(serializer),
            Vote::OurKey { key, .. } => key.serialize(serializer),
            Vote::TheirKey { prefix, key } => (prefix, key).serialize(serializer),
            Vote::TheirKnowledge { prefix, key_index } => (prefix, key_index).serialize(serializer),
        }
    }
}
