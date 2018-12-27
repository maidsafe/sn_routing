// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

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
    pub our_info: SectionInfo,
    pub latest_info: SectionInfo,
}

impl Debug for GenesisPfxInfo {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "GenesisPfxInfo({:?}, gen_version: {}, latest_version: {})",
            self.our_info.prefix(),
            self.our_info.version(),
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
