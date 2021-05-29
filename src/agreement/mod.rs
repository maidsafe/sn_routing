// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod dkg;
mod dkg_msgs_utils;
mod proposal;
mod proven;
#[cfg(test)]
pub mod test_utils;

pub(crate) use self::{
    dkg::{DkgCommands, DkgVoter},
    dkg_msgs_utils::{DkgFailureProofSetUtils, DkgFailureProofUtils, DkgKeyUtils},
    proposal::{ProposalAggregator, ProposalError, ProposalUtils},
};
pub(crate) use bls_signature_aggregator::{Proof, ProofShare, SignatureAggregator};
pub use proven::ProvenUtils;
use serde::Serialize;

// Verify the integrity of `message` against `proof`.
pub(crate) fn verify_proof<T: Serialize>(proof: &Proof, message: &T) -> bool {
    bincode::serialize(message)
        .map(|bytes| proof.verify(&bytes))
        .unwrap_or(false)
}
