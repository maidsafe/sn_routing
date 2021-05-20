// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Proof, ProofShare, SectionSigned, SignatureAggregator};
use crate::{
    error::Result,
    messages::PlainMessage,
    section::{NodeOp, SectionAuthorityProvider, SectionChain},
};
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;
use xor_name::XorName;

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Proposal {
    // Proposal to add a node to oursection
    Online {
        node_op: NodeOp,
        // Previous name if relocated.
        previous_name: Option<XorName>,
        // The key of the destination section that the joining node knows, if any.
        their_knowledge: Option<bls::PublicKey>,
    },

    // Proposal to remove a node from our section
    Offline(NodeOp),

    // Proposal to update info about a section. This has two purposes:
    //
    // 1. To signal the completion of a DKG by the elder candidates to the current elders.
    //    This proposal is then signed by the newly generated section key.
    // 2. To update information about other section in the network. In this case the proposal is
    //    signed by an existing key from the chain.
    SectionInfo(SectionAuthorityProvider),

    // Proposal to change the elders (and possibly the prefix) of our section.
    // NOTE: the `SectionAuthorityProvider` is already signed with the new key. This proposal is only to signs the
    // new key with the current key. That way, when it aggregates, we obtain all the following
    // pieces of information at the same time:
    //   1. the new section authority provider
    //   2. the new key
    //   3. the signature of the new section authority provider using the new key
    //   4. the signature of the new key using the current key
    // Which we can use to update the section section authority provider and the section chain at
    // the same time as a single atomic operation without needing to cache anything.
    OurElders(SectionSigned<SectionAuthorityProvider>),

    // Proposal to accumulate the message at the source (that is, our section) and then send it to
    // its destination.
    AccumulateAtSrc {
        message: Box<PlainMessage>,
        proof_chain: SectionChain,
    },

    // Proposal to change whether new nodes are allowed to join our section.
    JoinsAllowed(bool),
}

impl Proposal {
    /// Create ProofShare for this proposal.
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
            &bincode::serialize(&SignableView(self)).map_err(|_| ProposalError::Invalid)?,
        ))
    }

    #[cfg(test)]
    #[allow(unused)]
    pub fn as_signable(&self) -> SignableView {
        SignableView(self)
    }
}

// View of a `Proposal` that can be serialized for the purpose of signing.
pub(crate) struct SignableView<'a>(&'a Proposal);

impl<'a> Serialize for SignableView<'a> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Proposal::Online { node_op, .. } => node_op.serialize(serializer),
            Proposal::Offline(node_op) => node_op.serialize(serializer),
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
