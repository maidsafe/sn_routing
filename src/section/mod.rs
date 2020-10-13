// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod elders_info;
mod member_info;
mod network;
mod network_stats;
mod prefix_map;
#[allow(clippy::module_inception)]
mod section;
mod section_keys;
mod section_peers;
mod section_proof_chain;
mod section_update_barrier;
mod shared_state;

#[cfg(test)]
pub(crate) use self::elders_info::gen_elders_info;
pub use self::{
    elders_info::{majority_count, EldersInfo},
    member_info::{MemberInfo, PeerState, MIN_AGE},
    network_stats::NetworkStats,
    section_keys::{SectionKeyShare, SectionKeysProvider},
    section_peers::SectionPeers,
    section_proof_chain::{ExtendError, SectionProofChain, TrustStatus},
};
pub(crate) use self::{
    network::Network,
    section::Section,
    section_update_barrier::SectionUpdateBarrier,
    shared_state::{SharedState, UpdateSectionKnowledgeAction},
};
