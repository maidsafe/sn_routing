// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// The `chain` submodule contains the `Chain` implementation, which we reexport here.

#[allow(clippy::module_inception)]
mod chain;
mod chain_accumulator;
mod config;
mod elders_info;
mod member_info;
mod network_event;
mod proof;
mod shared_state;

#[cfg(feature = "mock_base")]
pub use self::chain_accumulator::{UNRESPONSIVE_THRESHOLD, UNRESPONSIVE_WINDOW};
pub use self::{
    chain::{delivery_group_size, Chain, ParsecResetData, PollAccumulated, SectionKeyShare},
    chain_accumulator::AccumulatingProof,
    config::NetworkParams,
    elders_info::{quorum_count, EldersInfo},
    member_info::{AgeCounter, MemberInfo, MemberPersona, MemberState, MIN_AGE, MIN_AGE_COUNTER},
    network_event::{
        AccumulatedEvent, AccumulatingEvent, AckMessagePayload, EldersChange, EventSigPayload,
        IntoAccumulatingEvent, NetworkEvent, OnlinePayload, SendAckMessagePayload,
    },
    proof::{Proof, ProofSet},
    shared_state::{SectionKeyInfo, SectionProofChain},
};
#[cfg(feature = "mock_base")]
#[allow(unused)] // FIXME
use crate::{error::RoutingError, id::P2pNode, BlsPublicKey, Prefix, XorName};
use crate::{BlsPublicKeySet, PublicId};
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct GenesisPfxInfo {
    pub first_info: EldersInfo,
    pub first_bls_keys: BlsPublicKeySet,
    pub first_state_serialized: Vec<u8>,
    pub first_ages: BTreeMap<PublicId, AgeCounter>,
    pub latest_info: EldersInfo,
    pub parsec_version: u64,
}

impl Debug for GenesisPfxInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "GenesisPfxInfo({:?}, gen_version: {}, latest_version: {}, parsec_version {})",
            self.first_info.prefix(),
            self.first_info.version(),
            self.latest_info.version(),
            self.parsec_version,
        )
    }
}

#[cfg(feature = "mock_base")]
#[allow(unused)]
/// Test helper to create arbitrary proof.
pub fn section_proof_chain_from_elders_info(
    elders_info: &EldersInfo,
    key: BlsPublicKey,
) -> SectionProofChain {
    SectionProofChain::from_genesis(SectionKeyInfo::from_elders_info(&elders_info, key))
}

/// Test helper to create arbitrary elders nfo.
#[cfg(feature = "mock_parsec")]
pub fn elders_info_for_test(
    members: BTreeMap<PublicId, P2pNode>,
    prefix: Prefix<XorName>,
    version: u64,
) -> Result<EldersInfo, RoutingError> {
    EldersInfo::new_for_test(members, prefix, version)
}
