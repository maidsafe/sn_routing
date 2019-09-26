// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// The `chain` submodule contains the `Chain` implementation, which we reexport here.
pub(crate) mod bls_emu;
mod candidate;
#[allow(clippy::module_inception)]
mod chain;
mod chain_accumulator;
mod member_info;
mod network_event;
mod proof;
mod section_info;
mod shared_state;
#[cfg(any(test, feature = "mock_base"))]
mod test_utils;

#[cfg(any(test, feature = "mock_base"))]
pub use self::test_utils::verify_chain_invariant;
pub use self::{
    chain::{delivery_group_size, Chain, PrefixChangeOutcome},
    chain_accumulator::AccumulatingProof,
    member_info::{MemberInfo, MemberPersona, MemberState},
    network_event::{
        AccumulatingEvent, AckMessagePayload, ExpectCandidatePayload, NetworkEvent, OnlinePayload,
        SectionInfoSigPayload, SendAckMessagePayload,
    },
    proof::{Proof, ProofSet},
    section_info::SectionInfo,
    shared_state::{PrefixChange, SectionKeyInfo, SectionProofChain},
};
#[cfg(feature = "mock_base")]
use crate::{error::RoutingError, BlsPublicKeySet, Prefix, PublicId, XorName};
#[cfg(feature = "mock_base")]
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct GenesisPfxInfo {
    pub first_info: SectionInfo,
    pub first_state_serialized: Vec<u8>,
    pub latest_info: SectionInfo,
}

impl Debug for GenesisPfxInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "GenesisPfxInfo({:?}, gen_version: {}, latest_version: {})",
            self.first_info.prefix(),
            self.first_info.version(),
            self.latest_info.version(),
        )
    }
}

#[cfg(feature = "mock_base")]
/// Test helper to create arbitrary proof.
pub fn section_proof_chain_from_section_info(section_info: &SectionInfo) -> SectionProofChain {
    SectionProofChain::from_genesis(SectionKeyInfo::from_section_info(&section_info))
}

#[cfg(feature = "mock_base")]
/// Test helper to create arbitrary BLS key set.
pub fn bls_key_set_from_section_info(section_info: SectionInfo) -> BlsPublicKeySet {
    BlsPublicKeySet::from_section_info(section_info)
}

#[cfg(feature = "mock_base")]
/// Test helper to create arbitrary section info.
pub fn section_info_for_test(
    members: BTreeSet<PublicId>,
    prefix: Prefix<XorName>,
    version: u64,
) -> Result<SectionInfo, RoutingError> {
    SectionInfo::new_for_test(members, prefix, version)
}
