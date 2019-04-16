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
mod neighbour_sigs;
mod network_event;
mod proof;
mod section_info;
#[cfg(any(test, feature = "mock"))]
mod test_utils;

pub use self::chain::{Chain, PrefixChangeOutcome};
pub use self::neighbour_sigs::NeighbourSigs;
pub use self::network_event::NetworkEvent;
pub use self::proof::{Proof, ProofSet, ProvingSection};
pub use self::section_info::SectionInfo;
#[cfg(any(test, feature = "mock"))]
pub use self::test_utils::verify_chain_invariant;
use std::fmt::{self, Debug, Formatter};

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct GenesisPfxInfo {
    pub first_info: SectionInfo,
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

/// The change to our own section that is currently in progress.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ChainState {
    Normal,
    Splitting,
    Merging,
}
