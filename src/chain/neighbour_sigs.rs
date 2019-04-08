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

use super::{Proof, ProofSet, SectionInfo};
use std::fmt::{self, Debug, Formatter};

/// A neighbour's section info, together with a quorum of signatures from a version of our section.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct NeighbourSigs {
    /// The neighbour's section info.
    sec_info: SectionInfo,
    /// The version of our section that signed `sec_info`.
    our_version: u64,
    /// A set of signatures by members of `our_version` of our own section, signing `sec_info`.
    proofs: ProofSet,
}

impl NeighbourSigs {
    /// Returns a new `NeighbourSigs`, with signatures from `our_info`.
    pub fn new(sec_info: SectionInfo, proofs: ProofSet, our_info: &SectionInfo) -> NeighbourSigs {
        NeighbourSigs {
            sec_info: sec_info,
            our_version: *our_info.version(),
            proofs: proofs,
        }
    }

    /// Returns the neighbour's section info.
    pub fn sec_info(&self) -> &SectionInfo {
        &self.sec_info
    }

    /// Returns the version of our own section that signed this neighbour's section info.
    pub fn our_version(&self) -> u64 {
        self.our_version
    }

    /// Checks if the given section info of our own section is newer than the one we already know
    /// about, and our proofs are a quorum with respect to it. If that is the case, returns `true`
    /// and updates the version.
    pub fn update_version(&mut self, our_info: &SectionInfo) -> bool {
        if *our_info.version() > self.our_version && our_info.is_quorum(&self.proofs) {
            self.our_version = *our_info.version();
            true
        } else {
            false
        }
    }

    /// Returns the proofs, i.e. our own section's signatures of the neighbour's section info.
    pub fn proofs(&self) -> &ProofSet {
        &self.proofs
    }

    /// Adds a proof and returns `false` if it was already known.
    pub fn add_proof(&mut self, proof: Proof) -> bool {
        self.proofs.add_proof(proof)
    }
}

impl Debug for NeighbourSigs {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "NeighbourSigs({:?}, ..)", self.sec_info)
    }
}
