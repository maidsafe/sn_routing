// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Proof, ProofShare, SignatureAggregator};
use crate::{error::Result, messages::PlainMessageUtils};
use serde::{Serialize, Serializer};
use sn_messaging::node::Proposal;
use thiserror::Error;

pub trait ProposalUtils {
    fn prove(
        &self,
        public_key_set: bls::PublicKeySet,
        index: usize,
        secret_key_share: &bls::SecretKeyShare,
    ) -> Result<ProofShare>;

    fn as_signable(&self) -> SignableView;
}

impl ProposalUtils for Proposal {
    /// Create ProofShare for this proposal.
    fn prove(
        &self,
        public_key_set: bls::PublicKeySet,
        index: usize,
        secret_key_share: &bls::SecretKeyShare,
    ) -> Result<ProofShare> {
        Ok(ProofShare::new(
            public_key_set,
            index,
            secret_key_share,
            &bincode::serialize(&self.as_signable()).map_err(|_| ProposalError::Invalid)?,
        ))
    }

    fn as_signable(&self) -> SignableView {
        SignableView(self)
    }
}

// View of a `Proposal` that can be serialized for the purpose of signing.
pub struct SignableView<'a>(pub &'a Proposal);

impl<'a> Serialize for SignableView<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Proposal::Online { member_info, .. } => member_info.serialize(serializer),
            Proposal::Offline(member_info) => member_info.serialize(serializer),
            Proposal::SectionInfo(info) => info.serialize(serializer),
            Proposal::OurElders(info) => info.proof.public_key.serialize(serializer),
            // Proposal::TheirKey { prefix, key } => (prefix, key).serialize(serializer),
            // Proposal::TheirKnowledge { prefix, key } => (prefix, key).serialize(serializer),
            Proposal::AccumulateAtSrc { message, .. } => {
                message.as_signable().serialize(serializer)
            }
            Proposal::JoinsAllowed(joins_allowed) => joins_allowed.serialize(serializer),
        }
    }
}

// Aggregator of `Proposal`s.
#[derive(Default)]
pub(crate) struct ProposalAggregator(SignatureAggregator);

impl ProposalAggregator {
    pub fn add(
        &mut self,
        proposal: Proposal,
        proof_share: ProofShare,
    ) -> Result<(Proposal, Proof), ProposalError> {
        let bytes =
            bincode::serialize(&SignableView(&proposal)).map_err(|_| ProposalError::Invalid)?;
        let proof = self.0.add(&bytes, proof_share)?;
        Ok((proposal, proof))
    }
}

#[derive(Debug, Error)]
pub enum ProposalError {
    #[error("failed to aggregate signature shares: {0}")]
    Aggregation(#[from] bls_signature_aggregator::Error),
    #[error("invalid proposal")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{agreement, section};
    use anyhow::Result;
    use std::fmt::Debug;
    use xor_name::Prefix;

    #[test]
    fn serialize_for_signing() -> Result<()> {
        // Proposal::SectionInfo
        let (section_auth, _, _) =
            section::test_utils::gen_section_authority_provider(Prefix::default(), 4);
        let proposal = Proposal::SectionInfo(section_auth.clone());
        verify_serialize_for_signing(&proposal, &section_auth)?;

        // Proposal::OurElders
        let new_sk = bls::SecretKey::random();
        let new_pk = new_sk.public_key();
        let proven_section_auth = agreement::test_utils::proven(&new_sk, section_auth)?;
        let proposal = Proposal::OurElders(proven_section_auth);
        verify_serialize_for_signing(&proposal, &new_pk)?;

        Ok(())
    }

    // Verify that `SignableView(proposal)` serializes the same as `should_serialize_as`.
    fn verify_serialize_for_signing<T>(proposal: &Proposal, should_serialize_as: &T) -> Result<()>
    where
        T: Serialize + Debug,
    {
        let actual = bincode::serialize(&SignableView(proposal))?;
        let expected = bincode::serialize(should_serialize_as)?;

        assert_eq!(
            actual, expected,
            "expected SignableView({:?}) to serialize same as {:?}, but didn't",
            proposal, should_serialize_as
        );

        Ok(())
    }
}
