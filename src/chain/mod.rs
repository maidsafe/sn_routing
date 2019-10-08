// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// The `chain` submodule contains the `Chain` implementation, which we reexport here.
pub(crate) mod bls_emu;
#[allow(clippy::module_inception)]
mod chain;
mod chain_accumulator;
mod elders_info;
mod member_info;
mod network_event;
mod proof;
mod shared_state;

pub use self::{
    chain::{delivery_group_size, Chain, EldersChange, PrefixChangeOutcome},
    chain_accumulator::AccumulatingProof,
    elders_info::EldersInfo,
    member_info::{MemberInfo, MemberPersona, MemberState},
    network_event::{
        AccumulatingEvent, AckMessagePayload, NetworkEvent, SectionInfoSigPayload,
        SendAckMessagePayload,
    },
    proof::{Proof, ProofSet},
    shared_state::{PrefixChange, SectionKeyInfo, SectionProofChain},
};
#[cfg(feature = "mock_base")]
use crate::{error::RoutingError, BlsPublicKeySet, Prefix, PublicId, XorName};
#[cfg(feature = "mock_base")]
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct GenesisPfxInfo {
    pub first_info: EldersInfo,
    pub first_state_serialized: Vec<u8>,
    pub latest_info: EldersInfo,
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
pub fn section_proof_chain_from_elders_info(elders_info: &EldersInfo) -> SectionProofChain {
    SectionProofChain::from_genesis(SectionKeyInfo::from_elders_info(&elders_info))
}

#[cfg(feature = "mock_base")]
/// Test helper to create arbitrary BLS key set.
pub fn bls_key_set_from_elders_info(elders_info: EldersInfo) -> BlsPublicKeySet {
    BlsPublicKeySet::from_elders_info(elders_info)
}

#[cfg(feature = "mock_base")]
/// Test helper to create arbitrary elders nfo.
pub fn elders_info_for_test(
    members: BTreeSet<PublicId>,
    prefix: Prefix<XorName>,
    version: u64,
) -> Result<EldersInfo, RoutingError> {
    EldersInfo::new_for_test(members, prefix, version)
}
