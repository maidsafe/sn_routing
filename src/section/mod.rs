// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod elders_info;
mod member_info;
mod network_stats;
mod section_keys;
mod section_map;
mod section_members;
mod section_proof_chain;
mod shared_state;

pub use self::{
    elders_info::{quorum_count, EldersInfo},
    member_info::{AgeCounter, MemberInfo, MemberState, MIN_AGE, MIN_AGE_COUNTER},
    network_stats::NetworkStats,
    section_keys::{IndexedSecretKeyShare, SectionKeys, SectionKeysProvider},
    section_map::SectionMap,
    section_members::SectionMembers,
    section_proof_chain::{SectionProofChain, TrustStatus},
    shared_state::SharedState,
};

#[cfg(test)]
pub use self::section_keys::gen_secret_key;

use crate::consensus::AccumulatingProof;

#[derive(Debug, PartialEq, Eq)]
pub struct SplitCache {
    pub elders_info: EldersInfo,
    pub section_key: bls::PublicKey,
    pub proofs: AccumulatingProof,
}
