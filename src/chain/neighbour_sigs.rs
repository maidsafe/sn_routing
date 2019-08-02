// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{ProofSet, SectionInfo};
use std::fmt::{self, Debug, Formatter};

/// A neighbour's section info, together with a quorum of signatures from a version of our section.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct NeighbourSigs {
    /// The neighbour's section info.
    sec_info: SectionInfo,
}

impl NeighbourSigs {
    /// Returns a new `NeighbourSigs`, with signatures from `our_info`.
    pub fn new(sec_info: SectionInfo, _proofs: ProofSet, _our_info: &SectionInfo) -> NeighbourSigs {
        NeighbourSigs { sec_info: sec_info }
    }

    /// Returns the neighbour's section info.
    pub fn sec_info(&self) -> &SectionInfo {
        &self.sec_info
    }
}

impl Debug for NeighbourSigs {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "NeighbourSigs({:?}, ..)", self.sec_info)
    }
}
